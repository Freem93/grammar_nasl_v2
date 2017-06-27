#TRUSTED 9afce89d02dc6d4d4de53f3fff6bcde20d71816b0e59cb13c6fafd7e88fb72e5c714b7c0b324827f6db6da9412ab05a5166604e66d5362e4445f03fc58b6a52164050c5d4a5cea5e8e64d6ebecad4e7a52e1889bbd4dd49337302c544bd0f2fe43bf3105ba99d32353f5ace1bf161b78e757a9e4a76c587bf700aad2c0b1b9b9441ed01759c69a0895cb87887263bc33ad057b5f0053db5a4de139d026e86292678e4b0c85f69f6574e13cdd3cefa3ac56fd4f6d31579756059e908b09a06d56767af018a4da159cf25150d5b2729ec976d9ea330774f0770106a727246120ad207dd8b5f2b5242dc06b2fdf3871b753dd7c386a92b9226bb69906bab2e723c28f37732e9333effbc595f9eea6c16019153b93a8e4432fec45c0352ffc33f7f968b672b3e20606c3a02fd9acb53e21f6e3f158cf585d16b802b99860a1c43956aa22d1a722a8605552cf9a24d7273a16fcd9cbc0ea074beeb08f03015fb91c534e0c9e6996718422b50eacf2c97161fca4f2cdeb4a08ed968ecc43504e10a24354e0598c9413cae2cbd0830615c41521dc53786dd449b7767c0319a1cb545de221aac5e802ad661f4423b227d22fc94d99bf833964891a900c9de884706f4576eeb791290d2b473edcf33f6aadc99f909a46ddb680557b5ec64bbdbaa8f5fcaa55bd644b0f8cc8e2d79a27bfd453b369d8f88deb5a9aae907c14a2ca38a0d552
##
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
# buffer_stream.inc
# v1.2
#
# This include allows reading of multiple files, network, or string data 
#  in a windowed stream for parsing
#
##

global_var NSBS_STREAM_BUFFER,NSBS_STREAM_TYPE,NSBS_STREAM_CONTENT,
NSBS_STREAM_BUFFER_POINTER,NSBS_STREAM_FILE,NSBS_STREAM_STRING,
NSBS_STREAM_NETWORK, NSBS_STREAM;

NSBS_STREAM = make_array();

NSBS_STREAM_TYPE = "type";
NSBS_STREAM_CONTENT = "content";
NSBS_STREAM_BUFFER_POINTER = "pointer";
NSBS_STREAM_BLOCK_SIZE = "len";

NSBS_STREAM_FILE    = 1;
NSBS_STREAM_STRING  = 2;
NSBS_STREAM_NETWORK = 3;

##
# Initialize the stream 
#
# @param [type:int] A constant ID defines in the header
# @param [content:obj] the content location. string|file|socket
# @param [block_size:int] the size of the sliding window [default:4096]
# @param [id:string] a unique identifier for this stream
#
# @return 0
##
function nsbs_streamInit(type, content, block_size, id)
{
  local_var buf, nsbs_stream_settings, fd;

  if (isnull(block_size)) block_size = 4096;

  if (isnull(content))
    exit(1, "No content supplied to read.");

  if(isnull(id)) 
    exit(1, "No id supplied for this stream.");

  if(typeof(type) == "function")
  {
    #do nothing
  }
  else if (type == NSBS_STREAM_FILE)
  {
    fd = file_open(name:content, mode:"r");
    buf = file_read(fp:fd, length:10);
    if (isnull(buf))
    {
      file_close(fd);
      exit(1, "File descriptor supplied was not able to read the file.");
    }
    content = fd;
    
  }
  else if (type == NSBS_STREAM_NETWORK)
  {
    if (isnull(get_source_port(content)))
      exit(1, "Socket supplied to stream is not a valid socket.");
  }
  else if (type == NSBS_STREAM_STRING)
  {
    if (typeof(content) != "data" && typeof(content) != "string" )
      exit(1, "String supplied to stream is not a valid string.");
  }
  else
  {
    exit(1, "Invalid type defined for stream.");
  }

  nsbs_stream_settings = make_array(
    NSBS_STREAM_TYPE, type,
    NSBS_STREAM_CONTENT, content,
    NSBS_STREAM_BUFFER_POINTER, 0,
    NSBS_STREAM_BLOCK_SIZE, block_size
  );
  NSBS_STREAM[id] = nsbs_stream_settings;

  return 0;
}

##
# Read in a block of content from the stream
#
# @param [id:strimg] id for the stream
#
# return string block of content or NULL if error reading
##
function nsbs_streamRead(id)
{
  local_var buf;

  if (NSBS_STREAM[id][NSBS_STREAM_TYPE] == 0)
    exit(1, "nsbs_streamInit was not called or failed to initialize a type.");

  if (typeof(NSBS_STREAM[id][NSBS_STREAM_TYPE]) == "function")
  {
    return NSBS_STREAM[id][NSBS_STREAM_TYPE](id:id);
  }
  else if (NSBS_STREAM[id][NSBS_STREAM_TYPE] == NSBS_STREAM_FILE)
  {
    buf = _nsbs_readfrom_file(id:id);
    if (isnull(buf)) file_close(NSBS_STREAM[id][NSBS_STREAM_CONTENT]);
    return buf;
  }
  else if (NSBS_STREAM[id][NSBS_STREAM_TYPE] == NSBS_STREAM_NETWORK)
  {
    return _nsbs_readfrom_network(id:id);    
  }
  else if (NSBS_STREAM[id][NSBS_STREAM_TYPE] == NSBS_STREAM_STRING)
  {
    return _nsbs_readfrom_string(id:id);
  }
  else
  {
    exit(1, "Invalid type defined for stream.");
  }

  return NULL;
}

##
# seek forward in reading a buffer
#
# @param [offset:int] offset to start reading
# @param [id:string] id for the stream
#
# @return NULL
##
function nsbs_seek(offset, id)
{
  if (isnull(id)) exit(1, "No id suppled to function nsbs_seek");

  if (NSBS_STREAM[id][NSBS_STREAM_TYPE] == 0)
    exit(1, "nsbs_streamInit was not called or failed to initialize a type.");
  else if (NSBS_STREAM[id][NSBS_STREAM_TYPE] == NSBS_STREAM_NETWORK)
    exit(1, "Can not seek on network streams.");

  NSBS_STREAM[id][NSBS_STREAM_BUFFER_POINTER] = offset;
}

##
# function allows the changing of block size
# 
# @param [block_size:int] window size for reading
# @param [id:string] the stream identifier
#
# @return NULL
##
function nsbs_setBlockSize(block_size, id)
{
  if (isnull(block_size) || block_size < 1)
    exit(1, "Invalid block size supplied for nsbs_setBlockSize.");

  NSBS_STREAM[id][NSBS_STREAM_BLOCK_SIZE] = block_size;
}

##
# get the block size for the stream
#
# @param [id:string] the stream identifier
#
# @return int block size
##
function nsbs_getBlockSize(id)
{
  return NSBS_STREAM[id][NSBS_STREAM_BLOCK_SIZE];
}

##############################################
#------------ Private Functions -------------#
##############################################

##
# private function
# read a buffer in from the file stream
#
# @param [id:string] stream id
#
# @return string buffer of content
#   NULL if end of buffer
##
function _nsbs_readfrom_file(id)
{
  local_var buf;

  file_seek(
    fp:NSBS_STREAM[id][NSBS_STREAM_CONTENT],
    offset:NSBS_STREAM[id][NSBS_STREAM_BUFFER_POINTER]
  );
  NSBS_STREAM[id][NSBS_STREAM_BUFFER_POINTER] += NSBS_STREAM[id][NSBS_STREAM_BLOCK_SIZE];

  buf = file_read(
    fp:NSBS_STREAM[id][NSBS_STREAM_CONTENT], 
    length:NSBS_STREAM[id][NSBS_STREAM_BLOCK_SIZE]
  );

  if (strlen(buf) < 1) buf = NULL;

  return buf;
}

##
# private function
# read a buffer in from a string
# 
# @param [id:string] stream id
#
# @return string buffer of content
#   NULL if end of buffer
##
function _nsbs_readfrom_string(id)
{
  local_var buf;

  buf = substr(
    NSBS_STREAM[id][NSBS_STREAM_CONTENT], 
    NSBS_STREAM[id][NSBS_STREAM_BUFFER_POINTER],  
    NSBS_STREAM[id][NSBS_STREAM_BUFFER_POINTER]+(NSBS_STREAM[id][NSBS_STREAM_BLOCK_SIZE]-1)
  );
  NSBS_STREAM[id][NSBS_STREAM_BUFFER_POINTER]+= NSBS_STREAM[id][NSBS_STREAM_BLOCK_SIZE];
  if (strlen(buf) < 1) buf = NULL;

  return buf;
}

##
# private function
# read a buffer in from a socket
#
# @param [id:string] stream id
#
# @return string buffer of content
#   NULL if end of buffer
##
function _nsbs_readfrom_network(id)
{
  local_var buf;

  if (isnull(NSBS_STREAM[id])) return NULL;

  if (NSBS_STREAM[id]["socketSet"])
  {
    if (socket_pending(NSBS_STREAM[id][NSBS_STREAM_CONTENT]))
    {
      buf = recv(
        socket:NSBS_STREAM[id][NSBS_STREAM_CONTENT],
        length:NSBS_STREAM[id][NSBS_STREAM_BLOCK_SIZE]
      );
    }
    else
      return NULL;
  }
  else
  {
    buf = recv(
      socket:NSBS_STREAM[id][NSBS_STREAM_CONTENT],
      length:NSBS_STREAM[id][NSBS_STREAM_BLOCK_SIZE]
    );

    NSBS_STREAM[id]["socketSet"] = TRUE;
  }

  return buf;
}

