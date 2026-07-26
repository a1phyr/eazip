use eazip::{CompressionMethod, FileType};
use std::io::Write;

fn test_one(name: &str) {
    let mut ar = eazip::ArchiveReader::open(name).unwrap();

    let expected_len = match name {
        // Windows 10 does not encode directories nor support chinese characters
        "tests/windows10.zip" => 3,
        // Go does not support symlinks
        "tests/go.zip" => 4,
        _ => 5,
    };

    let len = ar.entries().len();
    assert_eq!(expected_len, len);

    for i in 0..len {
        let mut file = ar.get_by_index(i).unwrap();

        let content = std::io::read_to_string(file.read().unwrap()).unwrap();
        let meta = file.metadata();

        match meta.name() {
            "hello/" => {
                assert_eq!(meta.compression_method, CompressionMethod::STORE);
                assert_eq!(content, "");
                assert_eq!(meta.file_type, FileType::Directory);
            }
            "hello/Benoît.txt" => {
                assert!(content.is_empty() || content == "Hello!\n");
                assert_eq!(meta.file_type, FileType::File);
            }
            "hello/hello.txt" => {
                assert_eq!(content, "Hello!\n");
                assert_eq!(meta.file_type, FileType::File);
            }
            "hello/symlink" => match meta.file_type {
                FileType::File => assert_eq!(content, "Hello!\n"),
                FileType::Symlink => assert_eq!(content, "hello.txt"),
                FileType::Directory => panic!(),
            },
            "hello/你好.txt" => {
                assert_eq!(content, "Hello!\n");
                assert_eq!(meta.file_type, FileType::File);
            }
            name => panic!("{name:?}"),
        }
    }
}

#[test]
fn self_test() {
    let path = "tests/eazip.zip";
    let mut options = eazip::write::FileOptions::default();
    let data = b"Hello!\n".as_slice();

    let mut writer = eazip::ArchiveWriter::new(std::fs::File::create(path).unwrap());
    writer.add_directory("hello/").unwrap();
    writer.add_file("hello/Benoît.txt", data, &options).unwrap();
    writer.add_file("hello/hello.txt", data, &options).unwrap();
    writer.add_symlink("hello/symlink", "hello.txt").unwrap();

    options.modified_at = eazip::Timestamp::now();
    let mut file = writer.stream_file("hello/你好.txt", &options).unwrap();
    file.write_all(data).unwrap();
    file.finish().unwrap();

    writer.finish().unwrap();

    test_one(path);

    let _ = std::fs::remove_file(path);
}

#[test]
fn infozip() {
    test_one("tests/infozip.zip");
}

#[test]
fn gnome() {
    test_one("tests/gnome.zip");
}

#[test]
fn kde() {
    test_one("tests/kde.zip");
}

#[test]
fn github() {
    test_one("tests/github.zip");
}

#[test]
fn linux_7z() {
    test_one("tests/7z-linux.zip");
}
#[test]
fn windows_7z() {
    test_one("tests/7z-windows.zip");
}

#[test]
fn windows10() {
    test_one("tests/windows10.zip");
}

#[test]
fn windows11() {
    test_one("tests/windows11.zip");
}

#[test]
fn go() {
    test_one("tests/go.zip");
}

#[test]
fn python() {
    test_one("tests/python.zip");
}

#[test]
fn write_invalid_names() {
    let mut archive = eazip::ArchiveWriter::new(Vec::new());
    let options = eazip::write::FileOptions::default();

    archive
        .add_file("trailing slash/", std::io::empty(), &options)
        .unwrap_err();

    archive
        .add_file("duplicated", std::io::empty(), &options)
        .unwrap();
    archive
        .add_file("duplicated", std::io::empty(), &options)
        .unwrap_err();
    archive
        .add_file("./duplicated", std::io::empty(), &options)
        .unwrap_err();
    archive.add_directory("duplicated/").unwrap_err();

    archive
        .add_file("/absolute", std::io::empty(), &options)
        .unwrap_err();
    if cfg!(windows) {
        archive
            .add_file("C:/absolute", std::io::empty(), &options)
            .unwrap_err();
    }

    archive
        .add_file("test/../../../oops", std::io::empty(), &options)
        .unwrap_err();
    archive.stream_file("dir\\file.txt", &options).unwrap_err();
    archive
        .add_file("", std::io::empty(), &options)
        .unwrap_err();

    archive.add_directory("no trailing slash").unwrap_err();

    archive
        .add_file("still valid", std::io::empty(), &options)
        .unwrap();
}
