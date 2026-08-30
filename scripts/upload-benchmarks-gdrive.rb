#!/usr/bin/env ruby

require 'google/apis/drive_v3'
require 'googleauth'
require 'fileutils'
require 'find'

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

def create_folder(drive, name, parent_id)
  query = "mimeType='application/vnd.google-apps.folder' and name='#{name}' and '#{parent_id}' in parents and trashed=false"
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
end

def upload_file(drive, local_path, remote_name, parent_id)
  query = "name='#{remote_name}' and '#{parent_id}' in parents and trashed=false"
  result = drive.list_files(q: query, fields: 'files(id, name)')
  
  file_metadata = {
    name: remote_name,
    parents: [parent_id]
  }

  begin
    if result.files.any?
      puts "Updating #{local_path}..."
      file_id = result.files.first.id
      drive.update_file(file_id, upload_source: local_path)
    else
      puts "Uploading #{local_path}..."
      drive.create_file(file_metadata, upload_source: local_path)
    end
  rescue StandardError => e
    puts "Failed to upload #{local_path}: #{e.message}"
  end
end

DIRECTORIES = ['benchmarks/results', 'benchmarks/baselines', 'docs/evidence']

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
    
    relative_dir = File.dirname(path)
    filename = File.basename(path)
    
    # Ensure folder structure exists
    path_parts = relative_dir.split('/')
    current_path = '.'
    parent_id = folder_cache['.']
    
    path_parts.each do |part|
      next if part == '.'
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
