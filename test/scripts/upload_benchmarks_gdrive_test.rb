#!/usr/bin/env ruby

require 'fileutils'
require 'minitest/autorun'
require 'ostruct'
require 'stringio'
require 'tmpdir'

require_relative '../../scripts/upload-benchmarks-gdrive'

module Google
  module Apis
    module DriveV3
      File = Struct.new(:name, :mime_type, :parents, keyword_init: true)
    end
  end
end

class FakeDrive
  attr_reader :created_folders, :created_files, :updated_files, :queries

  def initialize(existing_files: {})
    @existing_files = existing_files
    @created_folders = []
    @created_files = []
    @updated_files = []
    @queries = []
    @next_id = 1
  end

  def list_files(q:, fields:)
    @queries << q
    OpenStruct.new(files: Array(@existing_files[q]))
  end

  def create_file(metadata, fields: nil, upload_source: nil)
    id = "id-#{@next_id}"
    @next_id += 1

    if upload_source
      @created_files << [metadata, upload_source]
    else
      @created_folders << metadata
    end

    OpenStruct.new(id: id)
  end

  def update_file(file_id, upload_source:)
    @updated_files << [file_id, upload_source]
  end
end

class FailingDrive < FakeDrive
  def create_file(metadata, fields: nil, upload_source: nil)
    raise 'boom' if upload_source

    super
  end
end

class FolderFailingDrive < FakeDrive
  def list_files(q:, fields:)
    raise 'PERMISSION_DENIED: Request had insufficient authentication scopes.'
  end
end

class BenchmarkDriveUploaderTest < Minitest::Test
  def test_dry_run_scans_files_without_drive
    Dir.mktmpdir do |tmp|
      Dir.chdir(tmp) do
        FileUtils.mkdir_p('benchmarks/results/run-1')
        File.write('benchmarks/results/run-1/result.json', '{}')

        output = StringIO.new
        uploader = BenchmarkDriveUploader.new(
          drive: nil,
          root_folder_id: 'root',
          directories: ['benchmarks/results'],
          dry_run: true,
          output: output
        )

        assert uploader.run
        assert_equal 1, uploader.uploaded_files
        assert_includes output.string, 'Would upload benchmarks/results/run-1/result.json'
      end
    end
  end

  def test_upload_creates_nested_folders_and_file
    Dir.mktmpdir do |tmp|
      Dir.chdir(tmp) do
        FileUtils.mkdir_p('benchmarks/results/run-1/raw')
        File.write('benchmarks/results/run-1/raw/result.json', '{}')
        drive = FakeDrive.new

        uploader = BenchmarkDriveUploader.new(
          drive: drive,
          root_folder_id: 'root',
          directories: ['benchmarks/results'],
          output: StringIO.new
        )

        assert uploader.run
        assert_equal ['benchmarks', 'results', 'run-1', 'raw'], drive.created_folders.map(&:name)
        assert_equal ['result.json'], drive.created_files.map { |metadata, _source| metadata.name }
        assert_equal 1, uploader.uploaded_files
      end
    end
  end


  def test_upload_updates_existing_remote_file
    Dir.mktmpdir do |tmp|
      Dir.chdir(tmp) do
        FileUtils.mkdir_p('benchmarks/results')
        File.write('benchmarks/results/result.json', '{}')
        existing_query = "name='result.json' and 'id-2' in parents and trashed=false"
        drive = FakeDrive.new(existing_files: {
          existing_query => [OpenStruct.new(id: 'existing-file')]
        })

        uploader = BenchmarkDriveUploader.new(
          drive: drive,
          root_folder_id: 'root',
          directories: ['benchmarks/results'],
          output: StringIO.new
        )

        assert uploader.run
        assert_equal [['existing-file', 'benchmarks/results/result.json']], drive.updated_files
        assert_empty drive.created_files
      end
    end
  end

  def test_query_values_escape_quotes_and_backslashes
    assert_equal "O\\'Brien", BenchmarkDriveUploader.escape_query_value("O'Brien")
    assert_equal 'a\\\\b', BenchmarkDriveUploader.escape_query_value('a\\b')
  end

  def test_upload_failure_returns_false
    Dir.mktmpdir do |tmp|
      Dir.chdir(tmp) do
        FileUtils.mkdir_p('benchmarks/results')
        File.write('benchmarks/results/result.json', '{}')

        uploader = BenchmarkDriveUploader.new(
          drive: FailingDrive.new,
          root_folder_id: 'root',
          directories: ['benchmarks/results'],
          output: StringIO.new
        )

        refute uploader.run
        assert_equal ['benchmarks/results/result.json: boom'], uploader.failures
      end
    end
  end

  def test_folder_failure_returns_false_without_raising
    Dir.mktmpdir do |tmp|
      Dir.chdir(tmp) do
        FileUtils.mkdir_p('benchmarks/results')
        File.write('benchmarks/results/result.json', '{}')
        output = StringIO.new

        uploader = BenchmarkDriveUploader.new(
          drive: FolderFailingDrive.new,
          root_folder_id: 'root',
          directories: ['benchmarks/results'],
          output: output
        )

        refute uploader.run
        assert_includes output.string, 'Failed to process benchmarks/results'
        assert_includes output.string, 'GOOGLE_APPLICATION_CREDENTIALS'
        assert_includes output.string, 'gcloud auth application-default login --client-id-file=CLIENT_SECRET_JSON --scopes=https://www.googleapis.com/auth/cloud-platform,https://www.googleapis.com/auth/drive'
      end
    end
  end

  def test_folder_not_found_message_points_to_service_account_folder_share
    message = BenchmarkDriveUploader.format_error(RuntimeError.new('notFound: File not found: folder-id.'))

    assert_includes message, 'share the destination Drive folder with the service account email as Editor'
  end

  def test_load_dotenv_reads_quoted_values
    Dir.mktmpdir do |tmp|
      path = File.join(tmp, '.env')
      File.write(path, "DRIVE_FOLDER_ID=\"folder-123\"\n# ignored\nEMPTY=\n")

      without_env('DRIVE_FOLDER_ID', 'EMPTY') do
        load_dotenv(path)

        assert_equal 'folder-123', ENV.fetch('DRIVE_FOLDER_ID')
        assert_equal '', ENV.fetch('EMPTY')
      end
    end
  end

  def test_load_dotenv_does_not_override_exported_environment
    Dir.mktmpdir do |tmp|
      path = File.join(tmp, '.env')
      File.write(path, "DRIVE_FOLDER_ID=\"from-dotenv\"\n")

      with_env('DRIVE_FOLDER_ID' => 'from-env') do
        load_dotenv(path)

        assert_equal 'from-env', ENV.fetch('DRIVE_FOLDER_ID')
      end
    end
  end

  private

  def without_env(*keys)
    saved = keys.to_h { |key| [key, ENV[key]] }
    keys.each { |key| ENV.delete(key) }
    yield
  ensure
    saved.each do |key, value|
      value.nil? ? ENV.delete(key) : ENV[key] = value
    end
  end

  def with_env(values)
    saved = values.keys.to_h { |key| [key, ENV[key]] }
    values.each { |key, value| ENV[key] = value }
    yield
  ensure
    saved.each do |key, value|
      value.nil? ? ENV.delete(key) : ENV[key] = value
    end
  end
end
