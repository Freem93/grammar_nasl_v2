# Libraries we need
include("byte_func.inc");

# 5.0 doesn't have pass by ref, so for now
# we're going with a 'global' __BDB185_CTX
# we are limited to a single "instance"
# of the BDB185 'object' at a time
global_var __BDB185_CTX;

#######################################################
# Parses a Berkley DB 1.85 certificate store and 
# finds the SHA1 signatures of each certificate
#
# @param bddata binary blob data of certificate database
#
# @remark All SHA1 finger prints are encoded with hexstr()
#         in upper case
#
# @return array:
# {
#   "ERROR" : string error message if parsing data failed
#             will be NULL if no error occurred
#   "SIGS"  : array with structure 
#   {
#      "Cert1 SHA1 digest" : "Cert1 Nickname",
#      ...
#      "CertN SHA1 digest" : "CertN Nickname"
#   }
# }
function cert8db_get_cert_sigs(dbdata)
{

  # Catch dev errors
  if(isnull(dbdata) || typeof(dbdata) != 'data')
  {
    err_print('The dbdata parameter of cert8db_get_cert_sigs is NULL or an invalid type.\n');
    return NULL;
  }

  local_var rv,table,hash,key,data,pos,clen,nlen,nick,cert,sigs,dat;
  
  rv = make_array(
    "ERROR", NULL,
    "SIGS" , NULL
  );

  # Return BDB parsing error
  BDB185_load(data:dbdata);
  if(!isnull(__BDB185_CTX["ERROR"]))
  {
    rv["ERROR"] = __BDB185_CTX["ERROR"];
    return rv;
  }

  table = __BDB185_CTX["TABLE"];
  hash  = NULL; # Current BDB key MD5 hash
  key   = NULL; # Current BDB raw key data
  dat   = ''; # Raw binary data for cert entry
  pos   = 0;  # Read position in dat
  clen  = 0;  # Certificate length
  nlen  = 0;  # Certificate nick name length
  nick  = ''; # Certificate nick name data
  cert  = ''; # Certificate raw cert data
  sigs  = make_array();
  foreach hash (keys(table))
  {
    key = table[hash]["Key"];
    # Only certificate entries start with 0x01 in key data
    if(ord(key[0]) == 1)
    {
      dat  = __BDB185_getRawData(hashkey:hash);
      pos  = 9; # Skip certificate flags
      clen = getword(blob:dat,pos:pos);
      pos += 2;
      nlen = getword(blob:dat,pos:pos);
      pos += 2;
      cert = substr(dat,pos,pos+clen-1);
      pos += clen;
       # -2 removes trailing \0
       # Note : Nick name can be NULL
      nick = substr(dat,pos,pos+nlen-2);
      if(isnull(nick)) nick = "";
      sigs[toupper(hexstr(SHA1(cert)))] = nick;
    }
  }
  rv["SIGS"] = sigs;
  return rv;
}

#######################################################
# Loads a Berkley DB (v1.85) from a binary datablob
#
# @remark Always check __BDB185_CTX["ERROR"] == NULL before
#         performing further operations
#
# @remark See __BDB185_HDR_ORDER for more information
#         on __BDB185_CTX["HEADER"]
#
# @remark See __BDB185_loadRegularPage and
#         __BDB185_getRawData for more information about
#         __BDB185_CTX['TABLE']
#
# @param data : raw byte data of bdb file
#
# @return __BDB185_CTX array:
# {
#   "ERROR"  : error value as string (will be null for no error)
#   "DATA"   : copy of the data argument passed in
#   "HEADER" : header array read
#   {
#       "magic"     : int hash magic read from header
#       "version"   : int hash version read from header
#        ...
#       "h_charkey" : charkey hash
#   }
#   "SPARES"  : list of bdb 'spare' page
#   "BITMAPS" : list of bdb 'bitmaps'
#   "TABLE" : table array look up for key hash to data offsets
#    {
#       "Key1 MD5 Sum" : array of key information
#       {
#         "Key"       : key's raw byte data
#         "DataStart" : location in __BDB185_CTX['DATA'] where entries data starts
#         "DataEnd"   : location in __BDB185_CTX['DATA'] where entries data ends (inclusive)
#       },
#       ...
#       "KeyN MD5 Sum" { ... }
#    }
# }
function BDB185_load(data)
{
  __BDB185_CTX = make_array(
    "ERROR"   , NULL,
    "HEADER"  , NULL,
    "DATA"    , NULL,
    "SPARES"  , NULL,
    "BITMAPS" , NULL,
    "TABLE"   , make_array()
  );

  # Catch developer mistakes
  if(isnull(data) || typeof(data) != "data")
  {
    err_print('The data parameter of BDB185_load is NULL or an invalid type.\n');
    return NULL;
  }

  __BDB185_CTX['DATA'] = data;

  if(!__BDB185_loadHeader())
    return __BDB185_CTX;

  if(!__BDB185_loadPages())
    return __BDB185_CTX;

  return __BDB185_CTX;
}

##########################
## PRIVATE LIBRARY AREA ##
##########################

# Global constants
global_var __BDB185_HASHMAGIC,
           __BDB185_HASHVERSION,
           __BDB185_CHARKEY,
           __BDB185_OVERPAGE,
           __BDB185_PART_KEY,
           __BDB185_KEY_DATA,
           __BDB185_REAL_KEY,
           __BDB185_NCACHED,
           __BDB185_HDR_ORDER;

__BDB185_HASHMAGIC   = 0x061561;
__BDB185_HASHVERSION = 2;
__BDB185_CHARKEY     = '%$sniglet^&\0';
__BDB185_OVERPAGE    = 0;
__BDB185_PART_KEY    = 1;
__BDB185_FULL_KEY    = 2;
__BDB185_KEY_DATA    = 3;
__BDB185_REAL_KEY    = 4;
__BDB185_NCACHED     = 32;

# Page header elements
__BDB185_HDR_ORDER = make_list(
  "magic",      # Hash magic value single dword
  "version",    # Hash version single dword
  "lorder",     # Byte order single dword
  "bsize",      # Bucket/Page size single dword
  "bshift",     # Bucket shift single dword
  "dsize",      # Directory size single dword
  "ssize",      # Segment size single dword
  "sshift",     # Segment shift single dword
  "over_point", # Overflow pages start single dword
  "last_freed", # Last overflow page freed single dword
  "max_bucket", # Maximum bucket ID used single dword
  "high_mask",  # Mask modulo for entire table single dword
  "low_mask",   # Mask modulo for lower half of table single dword
  "ffactor",    # Fill factor single dword
  "nkeys",      # Number of keys single dword
  "hdrpages",   # Table header size single dword
  "h_charkey"   # Value of hash(CHARKEY) single dword
);

#######################################################
# Populates HEADER, SPARES and BITMAPS elements of 
# __BDB185_CTX
#
# @remark sets ERROR if there is an error parsing the
#         header
#
# @return TRUE  if header populated successfully
#         FALSE if there was an error
function __BDB185_loadHeader()
{
  local_var val,pos,header,hdr,i,spares,bitmaps,value;
  
  val = 0;
  pos = 0;

  # Load header 
  header = make_array();
  hdr    = "";

  foreach hdr (__BDB185_HDR_ORDER)
  {
    val  = getdword(blob:__BDB185_CTX["DATA"],order:BYTE_ORDER_BIG_ENDIAN,pos:pos);
    pos += 4; # Next dword

    # Error checking
    if(isnull(val))
      __BDB185_CTX["ERROR"] = "Corrupt DB : Premature end of data while parsing '"+hdr+"' header value.";
    else if(hdr == "magic" && val != __BDB185_HASHMAGIC)
      __BDB185_CTX["ERROR"] = "Hash type '"+val+"' not supported.";
    else if(hdr == "version" && val != __BDB185_HASHVERSION)
      __BDB185_CTX["ERROR"] = "Version '"+val+"' not supported.";
    else if(hdr == "h_charkey" && val != __BDB185_hash(key:__BDB185_CHARKEY))
      __BDB185_CTX["ERROR"] = "Hash function used is not compatible.";
    else if(hdr == "bsize" && strlen(__BDB185_CTX["DATA"])%val != 0)
      __BDB185_CTX["ERROR"] = "Corrupt DB : File size not evenly divisible by page size.";
    if(__BDB185_CTX["ERROR"] != NULL)
      return FALSE;

    # Translate byte order to Nessus global
    if(hdr == "lorder" && val == 1234)
      val = BYTE_ORDER_LITTLE_ENDIAN;
    else if(hdr == "lorder" && val != 1234)
      val = BYTE_ORDER_BIG_ENDIAN;

    header[hdr] = val;
  }
  __BDB185_CTX["HEADER"] = header;

  # Load spares
  spares = make_list();
  for(i = 0; i < __BDB185_NCACHED; i++)
  {
    val  = getdword(blob:__BDB185_CTX["DATA"],order:BYTE_ORDER_BIG_ENDIAN,pos:pos);
    pos += 4;
    if(isnull(val))
    {
      __BDB185_CTX["ERROR"] = "Corrupt DB : Premature end of data while reading spares.";
      return FALSE;
    }
    spares = make_list(spares,val);
  }
  __BDB185_CTX["SPARES"] = spares;

  bitmaps = make_list();
  for(i = 0; i < __BDB185_NCACHED; i++)
  {
    val  = getdword(blob:__BDB185_CTX["DATA"],order:BYTE_ORDER_BIG_ENDIAN,pos:pos);
    pos += 4;
    if(isnull(val))
    {
      __BDB185_CTX["ERROR"] = "Corrupt DB : Premature end of data while reading bitmaps.";
      return FALSE;
    }
    bitmaps = make_list(bitmaps,val);
  }
  __BDB185_CTX["BITMAPS"] = bitmaps;

  return TRUE;
}

#######################################################
# Populates TABLE of __BDB185_CTX, the DATA, HEADER, SPARES 
# items must already be set 
#
# @remark sets ERROR if there is an error parsing any
#         page
#
# @return TRUE  if there was no error
#         FALSE if there was an error
function __BDB185_loadPages()
{
  local_var bucket,pagenum,bsize,buckets,pointers,address,tbucket,overflows;

  bucket = 0;
  pagenum = 0;
  bsize = __BDB185_CTX["HEADER"]["bsize"];
  buckets = __BDB185_CTX["HEADER"]["max_bucket"];
  pointers = NULL;
  overflows = FALSE;

  for (bucket = 0; bucket <= buckets; bucket++)
  {
    pagenum = __BDB185_getBucketsPage(bucket:bucket);
    pointers = __BDB185_getPageOffsetPointers(pagenum:pagenum);
    if(isnull(pointers))
      return FALSE; # Parse error
    
    overflows = __BDB185_doesPageOverFlow(pagenum:pagenum);
    if(!__BDB185_loadRegularPage(pagenum:pagenum))
      return FALSE; # Parse error
    
    # Continue to load regular overflow pages in bucket
    while(overflows && pointers[1] != __BDB185_OVERPAGE && max_index(pointers) > 1)
    {
      # Get next page in bucket
      address = pointers[max_index(pointers) - 2];
      tbucket = (1 << (address >>> 11)) - 1;
      pagenum = __BDB185_getBucketsPage(bucket:tbucket) + (address & 0x7FF);

      if(pointers[1] < __BDB185_REAL_KEY)
      {
        # I've never encountered a Cert8.db file that has these pages
        # We don't support these "partial" pages at this time
        if(!__BDB185_loadPartialPage(pagenum:pagenum))
          return FALSE; # Error parsing
      }
      else
      {
        if(!__BDB185_loadRegularPage(pagenum:pagenum))
          return FALSE; # Error parsing
      }

      pointers = __BDB185_getPageOffsetPointers(pagenum:pagenum);
      if(isnull(pointers))
        return FALSE; # Error parsing

      overflows = __BDB185_doesPageOverFlow(pagenum:pagenum);
    }
  }
  # Signal no errors
  return TRUE;
}

#######################################################
# Populates loads a 'regular' database pages key/data
# information into __BDB185_CTXs TABLE item
#
# @param pagenum : valid page number to load
#
# @remark sets ERROR if there is an error parsing any
#         key or its data
#
# @return TRUE  if there was no error
#         FALSE if there was an error
function __BDB185_loadRegularPage(pagenum)
{
  local_var pageoffset,pointers,keynum,keyend,key,datoffset,keyhash,numkeys,keyoffset;

  pageoffset = __BDB185_getPageOffset(pagenum:pagenum);

  # Propagate Error
  numkeys = __BDB185_getPageEntryCount(pagenum:pagenum);
  if(isnull(numkeys))
    return FALSE;

  # Propagate error
  pointers = __BDB185_getPageOffsetPointers(pagenum:pagenum);
  if(isnull(pointers))
    return FALSE;

  # Load all keys
  keynum = 0;
  numkeys = numkeys / 2;
  if(__BDB185_doesPageOverFlow(pagenum:pagenum))
    numkeys -= 1;
  for (keynum = 0; keynum < numkeys; keynum++)
  {
    keyoffset  = pageoffset + pointers[keynum*2];
    keyend = pageoffset + __BDB185_CTX["HEADER"]["bsize"];
    if(keynum != 0)
      keyend = pageoffset + pointers[(keynum-1)*2 + 1];
    
    if(strlen(__BDB185_CTX["DATA"]) < keyend - 1 || keyoffset >= keyend - 1)
    {
      __BDB185_CTX["ERROR"] = "Corrupt DB : File corruption detected when reading "+pagenum+" key "+keynum+".";
      return FALSE;
    }
    key = substr(__BDB185_CTX["DATA"],keyoffset,keyend-1);

    datoffset = pageoffset + pointers[(keynum*2) + 1];
    if(strlen(__BDB185_CTX["DATA"]) < keyoffset - 1 || datoffset >= keyoffset - 1)
    {
      __BDB185_CTX["ERROR"] = "Corrupt DB : Premature end of file while parsing data for page "+pagenum+" key "+keynum+".";
      return FALSE;
    }

    keyhash = hexstr(MD5(key));
    if(!isnull(__BDB185_CTX["TABLE"][keyhash]))
    {
      __BDB185_CTX["ERROR"] = "Corrupt DB : Key collision on page "+pagenum+" key "+keynum+" hash "+keyhash+".";
      return FALSE;
    }

    __BDB185_CTX["TABLE"][keyhash] = make_array(
      "Key"      , key,
      "DataStart", datoffset,
      "DataEnd"  , keyoffset-1
    );
  }
  return TRUE;
}

#######################################################
# Loads a 'partial' database pages key/data information 
# into __BDB185_CTXs TABLE item
#
# @param pagenum : valid page number to load
#
# @remark Currently always returns an ERROR, we don't
#         support this kind of data/key fragmentation
#         and it is unclear whether we need to support
#         it or not for reading Cert8.db files, none
#         have had this type of fragmentation so far
#         and Firefox/Thunderbird seem to handle 
#         Certificates > bsize differently. I suspect
#         that when an entry's key data or actual
#         data exceeds the "page" size (bsize)
#         "partial" pages are use to handle the
#         overflow. So far I haven't been able to 
#         create such a database. --JimC
#
# @return TRUE  if there was no error
#         FALSE if there was an error
function __BDB185_loadPartialPage(pagenum)
{
  # I'm not sure whether we NEED to support this or not
  __BDB185_CTX["ERROR"] = "Partial pages are not supported.";
  return FALSE;
}

#######################################################
# Returns the raw data of a particular database entry
#
# @param hashkey : MD5 Sum of db key
#
# @return raw data for key or NULL if key does not exists
#
function __BDB185_getRawData(hashkey)
{
  local_var s,e;
  if(isnull(__BDB185_CTX["TABLE"][hashkey]))
    return NULL;
  s = __BDB185_CTX["TABLE"][hashkey]["DataStart"];
  e = __BDB185_CTX["TABLE"][hashkey]["DataEnd"  ];
  return substr(__BDB185_CTX["DATA"],s,e);
}

#######################################################
# Gets a page's offset within __BDB185_CTX['DATA']
#
# @param pagenum : valid page number
#
# @return where page starts in __BDB185_CTX['DATA']
#
function __BDB185_getPageOffset(pagenum)
{
  return pagenum*__BDB185_CTX["HEADER"]["bsize"];
}

#######################################################
# Gets a page's number of db entries aka the page's 
# offset pointer list length
#
# @param pagenum : valid page number
#
# @return NULL on error, page's entry count otherwise
#
function __BDB185_getPageEntryCount(pagenum)
{
  local_var offset,rv;
  offset = __BDB185_getPageOffset(pagenum:pagenum);
  rv = NULL;
  rv = getword(blob:__BDB185_CTX["DATA"],order:__BDB185_CTX["HEADER"]["lorder"],pos:offset);
  if(isnull(rv))
    __BDB185_CTX["ERROR"] = "Corrupt DB : Premature end of file while reading page entry count for page "+pagenum+".";
  return rv;
}

#######################################################
# Gets a page's "offset" pointers, which specify where
# db entry keys and data start with within a page
#
# @param pagenum : valid page number
#
# @return NULL on error, page's entry count otherwise
#
function __BDB185_getPageOffsetPointers(pagenum)
{
  local_var offset,entries,ptrs,loaded,ptr;

  offset  = __BDB185_getPageOffset(pagenum:pagenum);
  entries = __BDB185_getPageEntryCount(pagenum:pagenum);
  ptrs    = make_list();
  loaded  = 0;
  ptr     = NULL;

  # Propagate error
  if(isnull(entries))
    return NULL;

  while(loaded < entries)
  {
    ptr = getword(blob:__BDB185_CTX["DATA"],order:__BDB185_CTX["HEADER"]["lorder"],pos:offset+2+loaded*2);
    if(isnull(ptr))
    {
      __BDB185_CTX["ERROR"] = "Corrupt DB : Premature end of file while reading page offset pointers for page "+pagenum+".";
      return NULL;
    }
    ptrs[loaded] = ptr;
    loaded += 1;
  }
  return ptrs;
}

#######################################################
# Determines if a page overflows or not.
#
# @remark ERROR can be set after calling this function
#         it will always return FALSE in the case of
#         an error
#
# @param pagenum : valid page number
#
# @return TRUE  if page overflows
#         FALSE if page does not overflow
#
function __BDB185_doesPageOverFlow(pagenum)
{
  local_var entries, pointers;

  entries = __BDB185_getPageEntryCount(pagenum:pagenum);
  if(isnull(entries) || entries == 0)
    return FALSE;

  # File's corrupt, just return false ERROR has already been set for __BDB185_CTX
  pointers = __BDB185_getPageOffsetPointers(pagenum:pagenum);
  if(isnull(pointers))
    return FALSE;

  if(pointers[entries-1] == __BDB185_OVERPAGE)
    return TRUE;

  if(entries > 2 && pointers[1] < __BDB185_REAL_KEY)
    return TRUE;

  return FALSE;
}

#######################################################
# Gets a bucket's first page number
#
# @param bucket  : valid bucket number
#
# @returns bucket's first page
#
function __BDB185_getBucketsPage(bucket)
{
  local_var spare, lim, hdrp, spares, rv;

  spare  = 0;
  lim    = 1;
  while(lim < bucket+1)
  {
    lim = lim << 1;
    spare++;
  }

  hdrp   = __BDB185_CTX["HEADER"]["hdrpages"];
  spares = __BDB185_CTX["SPARES"];
  rv     = int(bucket) + hdrp;
  if(bucket != 0 && spare > 0)
    rv += spares[spare - 1];
  return rv;
}

#######################################################
# Hashes binary data using Berkley DB 1.85 Hash function
# version 2.
#
# @param key binary key data to hash
#
# @returns BDB 1.85 hash version 2 sum
#
function __BDB185_hash(key)
{
  local_var h,b;
  h = 0;
  b = 0;
  for(b = 0; b < strlen(key); b++)
    h = (h << 5) + h + ord(key[b]);
  return h;
}
