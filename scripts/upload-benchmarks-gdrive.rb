#!/usr/bin/env ruby

require 'google/apis/drive_v3'
require 'googleauth'
require 'fileutils'
require 'find'
require 'pathname'

# Prerequisites:
# gem install google-apis-drive_v3 googleauth
#
# Authentication:
# You must set GOOGLE_APPLICATION_CREDENTIALS environment variable
# to point to your Service Account JSON file.
# e.g., export GOOGLE_APPLICATION_CREDENTIALS="/path/to/credentials.json"
#
# Or, set up user credentials using `gcloud auth application-default login`
#
# Target Folder:
# Set the DRIVE_FOLDER_ID environment variable to the ID of the folder
# where you want to store these documents. If not set, it defaults to 'root'.

DRIVE_FOLDER_ID = ENV['DRIVE_FOLDER_ID'] || 'root'
REPO_ROOT = File.expand_path('..', __dir__)


drive = Google::Apis::DriveV3::DriveService.new
drive.client_options.application_name = 'Benchmark Uploader'

begin
  drive.authorization = Google::Auth.get_application_default(
    ['https://www.googleapis.com/auth/drive']
  )
rescue StandardError => e
  puts "Authentication failed. Please ensure GOOGLE_APPLICATION_CREDENTIALS is set."
  puts "Error: #{e.message}"
  exit 1
end

def handle_drive_error(action, error)
  message = error.message.to_s
  if message.include?('insufficient authentication scopes') || message.include?('access forbidden') || error.is_a?(Google::Apis::ClientError) && error.status_code == 403
    puts "Google Drive API authorization is missing the required scope."
    puts "Action: #{action}"
    puts "Required scope: https://www.googleapis.com/auth/drive"
    puts "Fix: re-authenticate with a credential that has Drive access, or set GOOGLE_APPLICATION_CREDENTIALS to the service account JSON."
    puts "Example: gcloud auth application-default login --scopes=https://www.googleapis.com/auth/drive"
    exit 1
  end

  puts "#{action} failed: #{message}"
end


def create_folder(drive, name, parent_id)
  query = "mimeType='application/vnd.google-apps.folder' and name='#{name}' and '#{parent_id}' in parents and trashed=false"

  begin
    result = drive.list_files(q: query, fields: 'files(id, name)')

    if result.files.any?
      result.files.first.id
    else
      folder_metadata = {
        name: name,
        mime_type: 'application/vnd.google-apps.folder',
        parents: [parent_id]
      }
      folder = drive.create_file(folder_metadata, fields: 'id')
      folder.id
    end
  rescue StandardError => e
    handle_drive_error("Creating folder '#{name}'", e)
    nil
  end
end


def upload_file(drive, local_path, remote_name, parent_id)
  query = "name='#{remote_name}' and '#{parent_id}' in parents and trashed=false"

  begin
    result = drive.list_files(q: query, fields: 'files(id, name)')

    file_metadata = {
      name: remote_name,
      parents: [parent_id]
    }

    if result.files.any?
      puts "Updating #{local_path}..."
      file_id = result.files.first.id
      drive.update_file(file_id, upload_source: local_path)
    else
      puts "Uploading #{local_path}..."
      drive.create_file(file_metadata, upload_source: local_path)
    end
  rescue StandardError => e
    handle_drive_error("Uploading '#{local_path}'", e)
    nil
  end
end

DIRECTORIES = ['benchmarks/results', 'benchmarks/baselines', 'docs/evidence'].map do |dir|
  File.expand_path(dir, REPO_ROOT)
end

# Cache folder IDs to avoid recreating/requerying
folder_cache = { '.' => DRIVE_FOLDER_ID }

DIRECTORIES.each do |dir|
  unless Dir.exist?(dir)
    puts "Directory #{dir} does not exist. Skipping."
    next
  end

  puts "Scanning #{dir}..."

  Find.find(dir) do |path|
    next if File.directory?(path)

    relative_path = Pathname.new(path).relative_path_from(Pathname.new(dir)).to_s
    relative_dir = File.dirname(relative_path)
    filename = File.basename(path)

    # Ensure folder structure exists
    path_parts = relative_dir == '.' ? [] : relative_dir.split(File::SEPARATOR)
    current_path = '.'
    parent_id = folder_cache['.']

    path_parts.each do |part|
      next if part == '.' || part.empty?
      new_path = current_path == '.' ? part : "#{current_path}/#{part}"

      unless folder_cache.key?(new_path)
        folder_cache[new_path] = create_folder(drive, part, parent_id)
      end

      current_path = new_path
      parent_id = folder_cache[new_path]
    end

    # Upload file
    upload_file(drive, path, filename, parent_id)
  end
end

puts "Upload complete!"
