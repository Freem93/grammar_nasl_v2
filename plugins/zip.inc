# -*- Fundamental -*-
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# zip.inc
# $Revision: 1.3 $
#

global_var _MAGIC_BOCD, _MAGIC_BOLH, _MAGIC_EOCD;

_MAGIC_BOCD = 0x02014b50; # Beginning of central directory.
_MAGIC_BOLH = 0x04034b50; # Beginning of local header.
_MAGIC_EOCD = 0x06054b50; # End of central directory.

global_var _ZIP_COMPRESSION_NONE, _ZIP_COMPRESSION_DEFLATE;

_ZIP_COMPRESSION_NONE = 0x00;
_ZIP_COMPRESSION_DEFLATE = 0x08;

##
# Formats an MS-DOS timestamp as human-readable text.
#
# @anonparam blob A 32-bit MS-DOS timestamp
#
# @return Timestamp in the form "YYYY-MM-DD HH:MM:SS"
##
function _msdos_time()
{
  local_var blob, day, hour, minute, month, second, year;

  blob = _FCT_ANON_ARGS[0];

  year   = (blob & 0xFE000000) >> 25;
  month  = (blob & 0x01E00000) >> 21;
  day    = (blob & 0x001F0000) >> 16;
  hour   = (blob & 0x0000F800) >> 11;
  minute = (blob & 0x000007E0) >>  5;
  second = (blob & 0x0000001F) >>  0;

  year += 1980;

  month  = _zero_pad(month);
  day    = _zero_pad(day);
  hour   = _zero_pad(hour);
  minute = _zero_pad(minute);
  second = _zero_pad(second);

  return year + "-" + month  + "-" + day + " " +
         hour + ":" + minute + ":" + second;
}

##
# Adds a zero in front of a single-digit integer.
#
# @anonparam num An integer
#
# @return A number with at least two digits
##
function _zero_pad()
{
  local_var num;

  num = _FCT_ANON_ARGS[0];

  if (num < 10)
    num = "0" + num;

  return string(num);
}

##
# Extracts and decompresses a file from the ZIP file.
#
# @param path The path of a file in the ZIP file.
# @param zip  A structure representing the ZIP file.
#
# @return A string with the contents of the file.
##
function _zip_extract(path, zip)
{
  local_var bs, cblob, file, magic, offset, ublob;

  # Make a shortcut to the file's metadata.
  file = zip["files"][path];
  if (isnull(file)) return NULL;

  # Make a shortcut to the backing store.
  bs = zip["bs"];
  if (isnull(bs)) return NULL;

  # Find the starting point for parsing.
  offset = file["offset"];

  # Ensure this is the right offset.
  magic = bsal_getdword(bs:bs, pos:offset);
  if (magic != _MAGIC_BOLH) return NULL;

  # Jump through the fixed-length fields.
  offset += 30;

  # Jump through the variable-length fields.
  offset +=
    bsal_getword(bs:bs, pos:offset - 4) +
    bsal_getword(bs:bs, pos:offset - 2);

  # Extract the compressed data.
  cblob = bsal_read(bs:bs, pos:offset, len:file["csize"]);

  # Decompress files compressed with supported algorithms.
  if (file["alg"] == 0)
    ublob = cblob;
  if (file["alg"] == 8)
    ublob = zlib_decompress(data:cblob, length:file["usize"]);
  else
    return NULL;

  # Verify the length of the uncompressed data.
  if (strlen(ublob) != file["usize"]) return NULL;

  return ublob;
}

##
# Extracts and decompresses files from a zip data structure.
#
# @param zip A structure representing the ZIP file.
#
# @anonparam path The path of a file in the ZIP file.
#
# @return Either a string, or a list of strings, with the contents of
#         the file(s).
##
function zip_extract(paths, zip)
{
  local_var blob, blobs, path, targets;

  # Create list of targets from named and anonymous arguments.
  targets = make_list();

  if (!isnull(paths))
    targets = make_list(targets, paths);

  if (!isnull(_FCT_ANON_ARGS))
    targets = make_list(targets, _FCT_ANON_ARGS);

  # Extract and decompress each file from the ZIP file.
  blobs = make_array();
  foreach path (targets)
  {
    blob = _zip_extract(zip:zip, path:path);
    blobs[path] = blob;
  }

  # If the caller only asked for one file, don't bother with an array.
  if (max_index(targets) == 1)
    return blob;

  return blobs;
}

##
# Parses a ZIP file into a NASL object.
#
# @param blob The contents of a ZIP file.
# @param fh   An SMB file handle.
#
# @anonparam path The path of a file in the ZIP file.
#
# @return A structure representing the ZIP, or an array containing the
#         decompressed contents of the requested paths.
##
function zip_parse(blob, smb)
{
  local_var arg, bs, blobs, file, len, magic, offset, path, zip;

  # Create an object to represent the backing store.
  bs = bsal_new(blob:blob, smb:smb);
  if (isnull(bs)) return NULL;

  # All values in ZIP files are little endian.
  set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

  # Ensure this is a ZIP file.
  magic = bsal_getdword(bs:bs, pos:0);
  if (magic != _MAGIC_BOLH) return NULL;

  # Search for the end of the central directory.
  len = bsal_length(bs:bs);
  for (offset = len - 4; offset >= 0; offset--)
  {
    magic = bsal_getdword(bs:bs, pos:offset);
    if (magic == _MAGIC_EOCD) break;
  }
  if (offset <= 0) return NULL;

  # Read where the start of the central directory is.
  offset = bsal_getdword(bs:bs, pos:offset + 16);
  magic = bsal_getdword(bs:bs, pos:offset);
  if (magic != _MAGIC_BOCD) return NULL;

  # Create structure to represent the ZIP file.
  zip = make_array();
  zip["bs"] = bs;
  zip["files"] = make_array();

  # Parse the files in the ZIP.
  while (TRUE)
  {
    # Check for the end of the central directory.
    magic = bsal_getdword(bs:bs, pos:offset);
    if (magic == _MAGIC_EOCD) break;

    # Check for the start of a file header.
    if (magic != _MAGIC_BOCD) return NULL;
    offset += 4;

    # Create structure to represent the file.
    file = make_array();

    # Pull out all the fields in the file header.
    file["mver"] = bsal_getword(bs:bs, pos:offset);
    offset += 2;

    file["ever"] = bsal_getword(bs:bs, pos:offset);
    offset += 2;

    file["flags"] = bsal_getword(bs:bs, pos:offset);
    offset += 2;

    file["alg"] = bsal_getword(bs:bs, pos:offset);
    offset += 2;

    file["timestamp"] = _msdos_time(bsal_getdword(bs:bs, pos:offset));
    offset += 4;

    file["chksum"] = bsal_getdword(bs:bs, pos:offset);
    offset += 4;

    file["csize"] = bsal_getdword(bs:bs, pos:offset);
    offset += 4;

    file["usize"] = bsal_getdword(bs:bs, pos:offset);
    offset += 4;

    file["fnsize"] = bsal_getword(bs:bs, pos:offset);
    offset += 2;

    file["efsize"] = bsal_getword(bs:bs, pos:offset);
    offset += 2;

    file["fcsize"] = bsal_getword(bs:bs, pos:offset);
    offset += 2;

    file["dnstart"] = bsal_getword(bs:bs, pos:offset);
    offset += 2;

    file["iattr"] = bsal_getword(bs:bs, pos:offset);
    offset += 2;

    file["eattr"] = bsal_getdword(bs:bs, pos:offset);
    offset += 4;

    file["offset"] = bsal_getdword(bs:bs, pos:offset);
    offset += 4;

    # Pull out the filename.
    path = bsal_read(bs:bs, pos:offset, len:file["fnsize"]);
    offset += file["fnsize"];

    # Ignore extra fields.
    offset += file["efsize"];

    # Pull out the file comment.
    file["comment"] = bsal_read(bs:bs, pos:offset, len:file["fcsize"]);
    offset += file["fcsize"];

    # If the caller didn't pass a list of paths, add the file to the
    # zip structure unconditionally.
    if (isnull(_FCT_ANON_ARGS))
    {
      zip["files"][path] = file;
      continue;
    }

    # If the caller passed a list of paths, only add the file to the
    # zip structure if it's in that list.
    foreach arg (_FCT_ANON_ARGS)
    {
      if (path == arg)
      {
        zip["files"][path] = file;
        break;
      }
    }
  }

  # Return the zip structure if the caller didn't pass a list of
  # paths.

  if (isnull(_FCT_ANON_ARGS))
    return zip;

  # If the caller passed a list of paths, extract them.
  return zip_extract(zip:zip, paths:keys(zip["files"]));
}

##
# Converts unix time to a ms-dos date
#
# @anonparam time a unix timestamp to convert
#
# @return a 16 bit ms-dos date or NULL on error
##
function dos_date()
{
  local_var time, ltime, dos_date;

  time = _FCT_ANON_ARGS[0];
  if (typeof(time) != "int")
  {
    err_print("Invalid argument passed to dos_date().");
    return NULL;
  }

  ltime = localtime(time);

  dos_date =
    (int(ltime['year'])-1980) << 9 |
    int(ltime['mon']) << 5 |
    int(ltime['mday']);

  return dos_date;
}

##
# Converts unix time to a ms-dos time
#
# @anonparam time a unix timestamp to convert
#
# @return a 16 bit ms-dos time or NULL on error
##
function dos_time()
{
  local_var time, ltime, dos_time;

  time = _FCT_ANON_ARGS[0];
  if (typeof(time) != "int")
  {
    err_print("Invalid argument passed to dos_time().");
    return NULL;
  }

  ltime = localtime(time);

  dos_time =
    int(ltime['hour']) << 11 |
    int(ltime['min']) << 5 |
    int(ltime['sec']);

  return dos_time;
}

##
# Calculates the crc32 as used in the ZIP format
#
# @anonparam data the data to calculate the crc32 of
#
# @return a 32 bit crc value
##
function _zip_crc32()
{
  local_var len, crc, i, data;

  data = _FCT_ANON_ARGS[0];
  if (isnull(data))
  {
    err_print("Invalid argument passed to _zip_crc32().");
    return NULL;
  }

  len = strlen(data);

  crc = 0xffffffff;

  for (i=0; i<len; i++)
    crc = ((crc >>> 8) & 0x00ffffff) ^ crc32tab[(crc ^ ord(data[i])) & 0xff];

  crc = crc ^ 0xffffffff;

  return crc;
}

##
# Creates a local file header for use in a zip file
#
# @param name the file name
# @param compressed_size the compressed size of the file
# @param compression_method the compression method used (_ZIP_COMPRESSION_NONE or _ZIP_COMPRESSION_DEFLATE)
# @param uncompressed_size the size of the file uncompressed
# @param time the file modified time in unix time format
# @param crc the zip crc32 of the uncompressed file
#
# @return a local file header for use in a zip file or NULL on error
##
function _zip_make_local_file_header(name, compressed_size, compression_method, uncompressed_size, time, crc)
{
  local_var name_length, modified_time, modified_date, file_header;


  if (isnull(name) || name == "")
  {
    err_print("Invalid name argument to _zip_make_local_file_header().");
    return NULL;
  }

  if (typeof(compressed_size) != "int" || compressed_size < 0)
  {
    err_print("Invalid compressed_size argument to _zip_make_local_file_header().");
    return NULL;
  }

  if (typeof(compression_method) != "int" || (compression_method != _ZIP_COMPRESSION_NONE && compression_method != _ZIP_COMPRESSION_DEFLATE))
  {
    err_print("Invalid compression_method argument to _zip_make_local_file_header().");
    return NULL;
  }

  if (typeof(uncompressed_size) != "int" || uncompressed_size < 0)
  {
    err_print("Invalid uncompressed_size argument to _zip_make_local_file_header().");
    return NULL;
  }

  if (typeof(time) != "int")
  {
    err_print("Invalid time argument to _zip_make_local_file_header().");
    return NULL;
  }

  if (typeof(crc) != "int")
  {
    err_print("Invalid crc argument to _zip_make_local_file_header().");
    return NULL;
  }

  name_length = strlen(name);

  modified_time = dos_time(time);
  modified_date = dos_date(time);

  if (isnull(modified_time) || isnull(modified_date))
  {
    err_print("Invalid time argument to _zip_make_local_file_header().");
    return NULL;
  }

  file_header =
    mkdword(_MAGIC_BOLH) +
    mkword(0x14) + # version 2.0
    mkword(0) + # bit flags, nothing special
    mkword(compression_method) +
    mkword(modified_time) +
    mkword(modified_date) +
    mkdword(crc) +
    mkdword(compressed_size) +
    mkdword(uncompressed_size) +
    mkword(name_length) +
    mkword(0) + # extra field length
    name;

  return file_header;
}

##
# Creates a central directory file header for use in a zip file
#
# @param name the file name
# @param compressed_size the compressed size of the file
# @param compression_method the compression method used (0x00 = none, 0x08 = DEFLATE)
# @param uncompressed_size the size of the file uncompressed
# @param offset the offset of the file header from the start of the zip file
# @param time the file modified time in unix time format
# @param crc the zip crc32 of the uncompressed file
#
# @return a central directory file header for use in a zip file or NULL on error
##
function _zip_make_central_directory_file_header(name, compressed_size, compression_method, uncompressed_size, offset, time, crc)
{
  local_var name_length, modified_time, modified_date, file_header;

  if (isnull(name) || name == "")
  {
    err_print("Invalid name argument to _zip_make_central_directory_file_header().");
    return NULL;
  }

  if (typeof(compressed_size) != "int" || compressed_size < 0)
  {
    err_print("Invalid compressed_size argument to _zip_make_central_directory_file_header().");
    return NULL;
  }

  if (typeof(compression_method) != "int" || (compression_method != _ZIP_COMPRESSION_NONE && compression_method != _ZIP_COMPRESSION_DEFLATE))
  {
    err_print("Invalid compression_method argument to _zip_make_central_directory_file_header().");
    return NULL;
  }

  if (typeof(uncompressed_size) != "int" || uncompressed_size < 0)
  {
    err_print("Invalid uncompressed_size argument to _zip_make_central_directory_file_header().");
    return NULL;
  }

  if (typeof(offset) != "int" || offset < 0)
  {
    err_print("Invalid offset argument to _zip_make_central_directory_file_header().");
    return NULL;
  }

  if (typeof(time) != "int")
  {
    err_print("Invalid time argument to _zip_make_central_directory_file_header().");
    return NULL;
  }

  if (typeof(crc) != "int")
  {
    err_print("Invalid crc argument to _zip_make_central_directory_file_header().");
    return NULL;
  }

  name_length = strlen(name);

  modified_time = dos_time(time);
  modified_date = dos_date(time);

  if (isnull(modified_time) || isnull(modified_date))
  {
    err_print("Invalid time argument to _zip_make_central_directory_file_header().");
    return NULL;
  }

  file_header =
    mkdword(_MAGIC_BOCD) +
    mkword(0x0314) + # UNIX, v2.0
    mkword(0x14) + # version 2.0
    mkword(0) + # no flags
    mkword(compression_method) +
    mkword(modified_time) +
    mkword(modified_date) +
    mkdword(crc) +
    mkdword(compressed_size) +
    mkdword(uncompressed_size) +
    mkword(name_length) +
    mkword(0) + # extra field length
    mkword(0) + # comment length
    mkword(0) + # disk # start
    mkword(0) + # internal attributes
    mkdword(0x81b40000) + # external attributes, -rw-rw-r--
    mkdword(offset) + # offset of local header from start of zip file
    name;

  return file_header;
}

##
# Creates a central directory footer for use in a zip file
#
# @param number_of_files the number of files in the archive
# @param directory_size the size in bytes of the central directory
# @param offset the offset of the central directory from the start of the zip file,
#
# @return a central directory footer for use in a zip file or NULL on error
##
function _zip_make_central_directory_footer(number_of_files, directory_size, offset)
{
  local_var footer;

  if (typeof(number_of_files) != "int" || number_of_files < 0)
  {
    err_print("Invalid number_of_files argument to _zip_make_central_directory_footer().");
    return NULL;
  }

  if (typeof(directory_size) != "int" || directory_size < 0)
  {
    err_print("Invalid directory_size argument to _zip_make_central_directory_footer().");
    return NULL;
  }

  if (typeof(offset) != "int" || offset < 0)
  {
    err_print("Invalid offset argument to _zip_make_central_directory_footer().");
    return NULL;
  }

  footer =
    mkdword(_MAGIC_EOCD) +
    mkword(0) + # disk number
    mkword(0) + # disk number that central directory starts on
    mkword(number_of_files) + # on this disk
    mkword(number_of_files) + # in total
    mkdword(directory_size) +
    mkdword(offset) +
    mkword(0); # comment length

  return footer;
}

##
# Creates a zip file
#
# @anonparam files A list of files to pack into a zip file. Each item is an array with
#                  a "name" and "contents" entry.
#
# @return a raw zip file, or NULL on error
##
function create_zip()
{
  local_var local_files, offset, number_of_files, central_directory, time;
  local_var file_contents, crc, file_header, central_file_header;
  local_var directory_size, central_footer, zip_file, compression_method;
  local_var uncompressed_size, compressed_size, files, file_name;
  local_var compressed_contents, file;

  files = _FCT_ANON_ARGS[0];

  if (typeof(files) != "array")
  {
    err_print("Invalid argument to create_zip() (not a list)");
    return NULL;
  }

  # All values in ZIP files are little endian.
  push_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

  local_files = "";
  offset = 0;
  number_of_files = 0;

  central_directory = "";

  time = unixtime();

  foreach file (files)
  {
    if (typeof(file) != "array")
    {
      err_print("Item in list passed to create_zipi() is not an array.");
      return NULL;
    }

    file_name = file["name"];
    file_contents = file["contents"];

    if (isnull(file_name) || file_name == "")
    {
      err_print("Item in list passed to create_zip() does not contain valid name.");
      return NULL;
    }

    if (isnull(file_contents))
    {
      err_print("Item in list passed to create_zip() does not contain valid contents.");
      return NULL;
    }

    uncompressed_size = strlen(file_contents);
    crc = _zip_crc32(file_contents);
    compressed_contents = zlib_compress(data:file_contents, level:9, strategy:Z_DEFAULT_STRATEGY);
    if (isnull(compressed_contents))
    {
      err_print("Compressing " + file_name + " failed.");
      return NULL;
    }

    compressed_size = strlen(compressed_contents);

    file_header = _zip_make_local_file_header(
      name:file_name,
      compressed_size:compressed_size,
      compression_method:_ZIP_COMPRESSION_DEFLATE,
      uncompressed_size:uncompressed_size,
      time:time,
      crc:crc
    );
    if (isnull(file_header))
    {
      err_print("_zip_make_local_file_header() failed.");
      return NULL;
    }

    offset = strlen(local_files);
    local_files += file_header + compressed_contents;

    central_file_header = _zip_make_central_directory_file_header(
      name:file_name,
      compressed_size:compressed_size,
      compression_method:_ZIP_COMPRESSION_DEFLATE,
      uncompressed_size:uncompressed_size,
      offset:offset,
      time:time,
      crc:crc
    );
    if (isnull(central_file_header))
    {
      err_print("_zip_make_central_directory_header() failed.");
      return NULL;
    }

    central_directory += central_file_header;

    number_of_files++;
  }

  directory_size = strlen(central_directory);

  offset = strlen(local_files);

  central_footer = _zip_make_central_directory_footer(number_of_files:number_of_files, directory_size:directory_size, offset:offset);
  if (isnull(central_footer))
  {
    err_print("_zip_make_central_directory_footer() failed.");
    return NULL;
  }

  zip_file = local_files + central_directory + central_footer;

  pop_byte_order();

  return zip_file;
}
