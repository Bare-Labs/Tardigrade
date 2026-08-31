#!/usr/bin/env ruby

require 'find'
require 'optparse'

# Prerequisites:
# gem install google-apis-drive_v3 googleauth
#
# Authentication:
# You must set GOOGLE_APPLICATION_CREDENTIALS environment variable
# to point to your Service Account JSON file.
# e.g., export GOOGLE_APPLICATION_CREDENTIALS="/path/to/credentials.json"
#
# Or, set up user credentials using `gcloud auth application-default login`
# with your own OAuth client ID. The default gcloud OAuth client may be blocked
# for Google Drive scopes.
#
# Target Folder:
# Set the DRIVE_FOLDER_ID environment variable to the ID of the folder
# where you want to store these documents. If not set, it defaults to 'root'.

class BenchmarkDriveUploader
  DEFAULT_DIRECTORIES = ['benchmarks/results', 'benchmarks/baselines', 'docs/evidence'].freeze
  DRIVE_FOLDER_MIME_TYPE = 'application/vnd.google-apps.folder'

  attr_reader :failures, :uploaded_files

  def initialize(drive:, root_folder_id:, directories: DEFAULT_DIRECTORIES, dry_run: false, output: $stdout)
    @drive = drive
    @root_folder_id = root_folder_id
    @directories = directories
    @dry_run = dry_run
    @output = output
    @folder_cache = { '.' => root_folder_id }
    @failures = []
    @uploaded_files = 0
  end

  def run
    @directories.each do |dir|
      upload_directory(dir)
    rescue StandardError => e
      failures << "#{dir}: #{format_error(e)}"
      @output.puts "Failed to process #{dir}: #{format_error(e)}"
    end

    if failures.empty?
      @output.puts @dry_run ? "Dry run complete. #{uploaded_files} file(s) would be uploaded." : "Upload complete! #{uploaded_files} file(s) uploaded."
      true
    else
      @output.puts "Upload finished with #{failures.length} failure(s)."
      false
    end
  end

  def self.escape_query_value(value)
    value.to_s.gsub('\\', '\\\\\\').gsub("'", "\\\\'")
  end

  def self.format_error(error)
    message = error.message
    if message.include?('insufficient authentication scopes')
      "#{message}. Use a service account shared on the destination Drive folder via GOOGLE_APPLICATION_CREDENTIALS, or run `gcloud auth application-default login --client-id-file=CLIENT_SECRET_JSON --scopes=https://www.googleapis.com/auth/cloud-platform,https://www.googleapis.com/auth/drive` with your own OAuth client ID."
    elsif message.include?('File not found')
      "#{message}. If this is a service account, share the destination Drive folder with the service account email as Editor and confirm DRIVE_FOLDER_ID points at that folder."
    else
      message
    end
  end

  private

  def format_error(error)
    self.class.format_error(error)
  end

  def upload_directory(dir)
    unless Dir.exist?(dir)
      @output.puts "Directory #{dir} does not exist. Skipping."
      return
    end

    @output.puts "Scanning #{dir}..."

    Find.find(dir) do |path|
      next if File.directory?(path)

      relative_dir = File.dirname(path)
      filename = File.basename(path)
      parent_id = ensure_remote_directory(relative_dir)
      upload_file(path, filename, parent_id)
    end
  end

  def ensure_remote_directory(relative_dir)
    parent_id = @folder_cache['.']
    current_path = '.'

    relative_dir.split('/').each do |part|
      next if part == '.'

      new_path = current_path == '.' ? part : "#{current_path}/#{part}"
      @folder_cache[new_path] ||= create_folder(part, parent_id)
      current_path = new_path
      parent_id = @folder_cache[new_path]
    end

    parent_id
  end

  def create_folder(name, parent_id)
    if @dry_run
      @output.puts "Would ensure folder #{name} under #{parent_id}"
      return "dry-run:#{parent_id}:#{name}"
    end

    query = [
      "mimeType='#{DRIVE_FOLDER_MIME_TYPE}'",
      "name='#{self.class.escape_query_value(name)}'",
      "'#{self.class.escape_query_value(parent_id)}' in parents",
      'trashed=false'
    ].join(' and ')
    result = @drive.list_files(q: query, fields: 'files(id, name)')

    return result.files.first.id if result.files.any?

    folder_metadata = Google::Apis::DriveV3::File.new(
      name: name,
      mime_type: DRIVE_FOLDER_MIME_TYPE,
      parents: [parent_id]
    )
    @drive.create_file(folder_metadata, fields: 'id').id
  end

  def upload_file(local_path, remote_name, parent_id)
    if @dry_run
      @output.puts "Would upload #{local_path} to #{parent_id}/#{remote_name}"
      @uploaded_files += 1
      return
    end

    query = [
      "name='#{self.class.escape_query_value(remote_name)}'",
      "'#{self.class.escape_query_value(parent_id)}' in parents",
      'trashed=false'
    ].join(' and ')
    result = @drive.list_files(q: query, fields: 'files(id, name)')

    begin
      if result.files.any?
        @output.puts "Updating #{local_path}..."
        @drive.update_file(result.files.first.id, upload_source: local_path)
      else
        @output.puts "Uploading #{local_path}..."
        file_metadata = Google::Apis::DriveV3::File.new(
          name: remote_name,
          parents: [parent_id]
        )
        @drive.create_file(file_metadata, upload_source: local_path)
      end
      @uploaded_files += 1
    rescue StandardError => e
      failures << "#{local_path}: #{e.message}"
      @output.puts "Failed to upload #{local_path}: #{e.message}"
    end
  end
end

def load_dotenv(path)
  return unless File.file?(path)

  File.foreach(path) do |line|
    stripped = line.strip
    next if stripped.empty? || stripped.start_with?('#')

    key, value = stripped.split('=', 2)
    next if key.nil? || value.nil? || key.empty?
    next if ENV.key?(key)

    value = value.strip
    if value.length >= 2 && ((value.start_with?('"') && value.end_with?('"')) || (value.start_with?("'") && value.end_with?("'")))
      value = value[1...-1]
    end
    ENV[key] = value
  end
end

def build_drive_service
  require 'google/apis/drive_v3'
  require 'googleauth'

  drive = Google::Apis::DriveV3::DriveService.new
  drive.client_options.application_name = 'Benchmark Uploader'
  drive.authorization = Google::Auth.get_application_default(
    ['https://www.googleapis.com/auth/drive']
  )
  drive
end

def parse_options(argv)
  load_dotenv(File.expand_path('../.env', __dir__))

  options = {
    dry_run: false,
    root_folder_id: ENV['DRIVE_FOLDER_ID'] || 'root',
    directories: BenchmarkDriveUploader::DEFAULT_DIRECTORIES
  }

  parser = OptionParser.new do |opts|
    opts.banner = "Usage: #{File.basename($PROGRAM_NAME)} [options] [DIRECTORY ...]"
    opts.on('--dry-run', 'Print the folders and files that would be uploaded without contacting Google Drive') do
      options[:dry_run] = true
    end
    opts.on('--folder-id ID', 'Google Drive destination folder ID (default: DRIVE_FOLDER_ID or root)') do |id|
      options[:root_folder_id] = id
    end
    opts.on('-h', '--help', 'Show this help') do
      puts opts
      exit 0
    end
  end

  parser.parse!(argv)
  options[:directories] = argv unless argv.empty?
  options
end

if $PROGRAM_NAME == __FILE__
  options = parse_options(ARGV)
  drive = nil

  unless options[:dry_run]
    begin
      drive = build_drive_service
    rescue StandardError => e
      warn 'Authentication failed. Please ensure GOOGLE_APPLICATION_CREDENTIALS is set or application-default credentials are available.'
      warn "Error: #{e.message}"
      exit 1
    end
  end

  uploader = BenchmarkDriveUploader.new(
    drive: drive,
    root_folder_id: options[:root_folder_id],
    directories: options[:directories],
    dry_run: options[:dry_run]
  )
  exit(uploader.run ? 0 : 1)
end
