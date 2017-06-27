###
# (C) Tenable Network Security, Inc.
#
# @NOGPL@
#
# $Revision: 1.2 $
#
# @include byte_func.inc
# @include smb_func.inc
###

global_var _BSAL_CACHE, _BSAL_CACHE_SIZE;

_BSAL_CACHE = NULL;
_BSAL_CACHE_SIZE = 1024;

##
# Reads an 8-bit integer from the backing store.
#
# @param bs  The backing store.
# @param pos The location at which to start reading.
#
# @return The requested bytes from the backing store.
##
function bsal_getbyte(bs, pos)
{
  return getbyte(blob:bsal_read(bs:bs, len:1, pos:pos), pos:0);
}

##
# Reads a 16-bit integer from the backing store.
#
# @param bs  The backing store.
# @param pos The location at which to start reading.
#
# @return The requested bytes from the backing store.
##
function bsal_getword(bs, pos)
{
  return getword(blob:bsal_read(bs:bs, len:2, pos:pos), pos:0);
}

##
# Reads a 32-bit integer from the backing store.
#
# @param bs  The backing store.
# @param pos The location at which to start reading.
#
# @return The requested bytes from the backing store.
##
function bsal_getdword(bs, pos)
{
  return getdword(blob:bsal_read(bs:bs, len:4, pos:pos), pos:0);
}

##
# Calculates the amount of data in the backing store.
#
# @param bs The backing store.
#
# @return The number of bytes in the backing store.
##
function bsal_length(bs)
{
  if (bs[0] == "BLOB")
    return strlen(bs[1]);

  if (bs[0] == "SMB")
    return GetFileSize(handle:bs[1]);

  return NULL;
}

##
# Reads bytes from the backing store.
#
# @param bs  The backing store.
# @param len The number of bytes to be read.
# @param pos The location at which to start reading.
#
# @return The requested bytes from the backing store.
##
function bsal_read(bs, len, pos)
{
  if (bs[0] == "BLOB")
    return substr(bs[1], pos, pos + len - 1);

  if (bs[0] == "SMB")
  {
    # Check if we can satisfy this request from the cache.
    if (_BSAL_CACHE["start"] <= pos && pos + len <= _BSAL_CACHE["end"])
    {
      # Recalculate position relative to cache's start.
      pos -= _BSAL_CACHE["start"];

      return substr(_BSAL_CACHE["blob"], pos, pos + len - 1);
    }

    # If request is large we don't want to cache it.
    if (len > _BSAL_CACHE_SIZE)
      return ReadFile(handle:bs[1], offset:pos, length:len);

    # Put a new chunk of data in the cache.
    _BSAL_CACHE["blob"] = ReadFile(handle:bs[1], offset:pos, length:_BSAL_CACHE_SIZE);
    if (isnull(_BSAL_CACHE["blob"])) return NULL;

    _BSAL_CACHE["start"] = pos;
    _BSAL_CACHE["end"] = strlen(_BSAL_CACHE["blob"]);

    return substr(_BSAL_CACHE["blob"], 0, len - 1);
  }

  return NULL;
}

##
# Creates a new backing store object.
#
# @param blob A string storing the contents of a file.
# @param smb  An SMB file handle.
#
# @return An object representing a backing store.
##
function bsal_new(blob, smb)
{
  local_var bs;

  # Create an object to represent the backing store.
  bs = make_array();

  if (!isnull(blob))
  {
    bs[0] = "BLOB";
    bs[1] = blob;

    return bs;
  }

  if (!isnull(smb))
  {
    bs[0] = "SMB";
    bs[1] = smb;

    _BSAL_CACHE = make_array(
      "start", -1,
      "end", -1,
      "blob", ""
    );

    return bs;
  }

  return NULL;
}
