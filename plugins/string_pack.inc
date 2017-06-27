#TRUSTED 51d51fc86bcab0ac337b7ecf9a7c790b86b08cd4c4e98c91881e70e1388c94aee5c55a95ba4d5ed2f9c822165d32c0c2a9fcd892fa4525fe9cbe9982a34ae680134f43ca7841001064750f0f80357d49a4ed4026be0c3f090b68bc1a76debde28aa30c2fa1d78c910877fb197a97cd1332b219c805b12100ddee9902c65e7911d13c72ece64d9c07daf7f5de380d2dc2085b78ee73553349de6266c16afda2a687a5d520960090748a4535465ef6d69b666dbd809947fd2f9b87c0da001261c868c00d628b0f71ae6f1e6a4191798636278d0b319223a8ebdf18f3c58101feb81ede1b6eb6b3b206ff06efd0307e18188d8ad16411146ddb29264fe3f5adaee2d99e40fac2af3410ae35112870e5643096b1389d30ebaf41837eabc3794d911a92eb393428e52554c7fad2f6413ffe8d74ab5983ec0c3fbb161ad9f4331e98ccd0bbbbc4cabf439e313409c36e82b243da9f414ca96ef8e46e1d96e6f71908e6aaade8e9d815dcab8545d62d3ec2eebc9b87cad353a85ddccda463d45b7867b8711ef54eccc21ea29449e86cb7e689a4325d5d6f62f919c453c041d5fbddc904e534e4b6cad39dc6f1730b593c78d76b081a3b60e22f0f56f5527062a0aa5087436d8089688f48b612324f5f562735254463e66ab716595fe068c2c9e8b14721156b0a398d1105c4776670b430d31d1e4b0b6594e628a563137c433d4bc1a77c
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# string_pack.inc
#
# Revision: 1.3
#
# @include byte_func.inc
#

###
# States for pack()/unpack().
#
# Note: Throughout this file, we use 'pack_*' as a naming convention,
# even when variables are used for both pack and unpack.
###
global_var
  _PACK_STATE_NEW,
  _PACK_STATE_HAVE_OPERATOR,
  _PACK_STATE_READY,
  _PACK_STATE_DONE;

_PACK_STATE_NEW           = 0;
_PACK_STATE_HAVE_OPERATOR = 1;
_PACK_STATE_KEYWORD       = 2;
_PACK_STATE_READY         = 3;
_PACK_STATE_DONE          = 4;

##
# A private helper function for pack()/unpack().
#
# Reset the 'state' to the initial state, and clear any state
# variables. Note that this doesn't remove everything from the state.
#
# @param state The state object.
#
# @return The new state object.
##
function _pack_reset_state(state)
{
  state["state"]       = _PACK_STATE_NEW;
  state["operator"]    = NULL;
  state["count"]       = "";
  state["byte_order"]  = BYTE_ORDER_BIG_ENDIAN;

  # pack() needs the keywords restarted for every operator.
  if (state["function"] == "pack")
  {
    # Note that a path object is similar to a list, so we need to treat
    # it as such when adding it to another list.
    state["keywords"] = make_list();
    state["keywords"][0] = state["kw"];
    state["keywords_pos"] = 0;
  }
  else
  {
    state["keyword_new"] = FALSE;

    # These are keywords that only apply to the '?' operator.
    state["count_keywords"] = make_list();
    state["count_keywords"][0] = state["result"];
    state["count_keywords_pos"] = 0;
  }

  return state;
}

##
# A private helper function for pack()/unpack().
#
# This function is called when we're in _PACK_STATE_NEW. It is passed
# the current character that's being processed, and expects it to be
# the operator. Valid operators are letters and '@' (not all letters
# are valid operators, but those will be caught later).
#
# This state is only valid for a single character, and always reads
# exactly one character.
#
# @param state The state object.
# @param c     The current character in the format string.
#
# @return The new state object.
##
function _pack_handle_state_new(c, state)
{
  state["operator"] = c;
  state["format_pos"]++;

  # Only allow defined operators.
  if (state["operator"] !~ "[a-zA-Z@[\]{}?]")
    return NULL;

  state["state"] = _PACK_STATE_HAVE_OPERATOR;

  return state;
}

##
# A private helper function for pack()/unpack().
#
# This function is called when we're in _PACK_STATE_HAVE_OPERATOR. It
# is passed the current character that's being processed, and expects
# it to be a modifier for the operator. That can be a count or a
# symbol (e.g., for endianness).
#
# This can process any number of operators / numbers, from 0 to no
# limit. As soon as something unexpected is encountered - generally a
# letter - the state goes to _PACK_STATE_READY.
#
# @param state The state object.
# @param c     The current character in the format string.
#
# @return The new state object.
##
function _pack_handle_state_have_operator(c, state)
{
  local_var type;

  # Numerical operators are concatenated to 'count'.
  if (c =~ "^[0-9]$")
  {
    if (state["count"] == "*")
      exit(1, "Illegal operator in pack/unpack: '*' followed by a number.");

    # Since we can have multi-digit numbers, just add the digit to the
    # end of count.
    state["count"] += c;
    state["format_pos"]++;
  }

  # The '*' operator is a special number.
  else if (c == "*")
  {
    if (state["count"] != "")
      exit(1, "Illegal operator in pack/unpack: a number followed by '*'.");

    state["count"] = "*";
    state["format_pos"]++;
  }

  # The '#' operator is a special number.
  else if (c == "#")
  {
    if (state["count"] != "")
      exit(1, "Illegal operator in pack/unpack: a number followed by '#'.");

    if (state["function"] == "pack")
      exit(1, "Illegal operator in pack: '#' is only permitted in unpack().");

    state["count"] = "#";
    state["format_pos"]++;
  }

  # The '(' operator starts a keyword.
  else if (c == "(")
  {
    if (state["operator"] =~ "[xX@]")
      exit(1, "Illegal operator in pack/unpack: 'x', 'X', and '@' make no sense when followed by a keyword.");

    if (state["operator"] =~ "[}\]]")
      exit(1, "Illegal operator in pack/unpack: ']' and '}' make no sense when followed by a keyword.");

    if (state["function"] == "pack" && isnull(state["kw"]))
      exit(1, "pack() used a keyword lookup when no keywords were provided.");

    # Determine what type of keywords we are seeing.
    if (state["operator"] == "?")
    {
      type = "count_keywords";
    }
    else
    {
      type = "keywords";
      state["keyword_new"] = TRUE;
    }

    # Start a new keyword.
    state[type][++state[type + "_pos"]] = "";

    state["format_pos"]++;
    state["state"] = _PACK_STATE_KEYWORD;
  }

  # The '<' operator is little endian.
  else if (c == "<")
  {
    if (state["operator"] !~ "[iIlLsStT]")
      exit(1, "Illegal operator in pack/unpack: '<' and '>' can only modify i, I, l, L, s, S, t, and T.");

    state["byte_order"] = BYTE_ORDER_LITTLE_ENDIAN;
    state["format_pos"]++;
  }

  # The '>' operator is big endian.
  else if (c == ">")
  {
    if (state["operator"] !~ "[iIlLsStT]")
      exit(1, "Illegal operator in pack/unpack: '<' and '>' can only modify i, I, l, L, s, S, t, and T.");

    state["byte_order"] = BYTE_ORDER_BIG_ENDIAN;
    state["format_pos"]++;
  }

  # The '!' operator is native endian (note: we ignore this).
  else if (c == "!")
  {
    exit(1, "Illegal operator in pack/unpack: '!' (native endian) not supported.");
  }

  # Everything else moves us into a new state.
  else
  {
    # Set up the count properly.
    #
    # If no count is given, assume one, and don't forget to handle '#'
    # and '*' when converting to an int().
    if (state["count"] == "")
      state["count"] = 1;
    else if (state["count"] == "#")
      state["count"] = state["dynamic_count"];
    else if (state["count"] != "*")
      state["count"] = int(state["count"]);

    state["state"] = _PACK_STATE_READY;
  }

  return state;
}

##
# A private helper function for pack()/unpack().
#
# This function is called when we're in _PACK_STATE_KEYWORD. It is
# passed the current character that's being processed, and expects it
# to be part of a keyword.
#
# There are two types of keywords, because different uses of keywords
# need to be treated differently. Normal keywords are for storage
# (unpack) and retrieval (pack) of items. 'count' keywords are only
# for indexing into the result set to allow for length-prefixed
# strings and arrays.
#
# @param state The state object.
# @param c     The current character in the format string.
#
# @return The new state object.
##
function _pack_handle_state_keyword(c, state)
{
  local_var type;

  # Determine what type of keywords we are seeing.
  if (state["operator"] == "?")
    type = "count_keywords";
  else
    type = "keywords";

  if (isnull(c))
  {
    state["state"] = _PACK_STATE_DONE;
  }
  else if (c == ")")
  {
    # If we have an numeric keyword, convert it so that we can index
    # into lists properly.
    if (state[type][state[type + "_pos"]] =~ "^\d+$")
      state[type][state[type + "_pos"]] = int(state[type][state[type + "_pos"]]);

    state["state"] = _PACK_STATE_HAVE_OPERATOR;
    state["format_pos"]++;
  }
  else
  {
    # Append character to the last keyword.
    state[type][state[type + "_pos"]] += c;
    state["format_pos"]++;
  }

  return state;
}

function _unpack_add(data, state)
{
  # You can only add to an array if you've declared a keyword for the
  # operator, since all array elements require names.
  if (state["types"][state["types_pos"]] == "array" && !state["keyword_new"])
    exit(1, "unpack() tried to add '" + state["operator"] + "' to an array without a keyword argument.");

  # Add the data to the innermost collection, as routed by the
  # keywords.
  path_set(args:state["keywords"], val:data);

  # The top-most keyword is no longer new.
  state["keyword_new"] = FALSE;

  # If we've added a list, and are going deeper...
  if (state["operator"] == "[")
  {
    state["types"][++state["types_pos"]] = "list";

    # Add a keyword so that future calls will add to the start of the
    # new list.
    state["keywords"][++state["keywords_pos"]] = 0;
  }

  # If we've added an array, and are going deeper...
  else if (state["operator"] == "{")
  {
    state["types"][++state["types_pos"]] = "array";
  }

  # If we've added a scalar, and are staying at this level...
  else
  {
    # If the current collection is a list, increment its keyword so
    # the next call to this function won't overwrite the data we just
    # appended.
    if (state["types"][state["types_pos"]] == "list")
      state["keywords"][state["keywords_pos"]]++;

    # If the current collection is an array, then we've just consumed
    # the final keyword, and we should pop it off to prevent
    # mis-routing later additions.
    else
      state["keywords"][state["keywords_pos"]--] = NULL;
  }

  return state;
}

function _unpack_pop(state)
{
  # Ensure the operator is capable of closing the inner collection.
  if (state["operator"] == "]")
  {
    if (state["types"][state["types_pos"]] != "list")
      exit(1, "Illegal operation in unpack(): Attempted to close array with ']'.");

    state["keywords"][state["keywords_pos"]--] = NULL;
  }
  else
  {
    if (state["types"][state["types_pos"]] != "array")
      exit(1, "Illegal operation in unpack(): Attempted to close list with '}'.");
  }

  # Remove the inner collection's type information.
  state["types"][state["types_pos"]--] = NULL;

  # If the outer collection is a list, increment its keyword so the
  # next call to this _unpack_add() won't overwrite anything.
  if (state["types"][state["types_pos"]] == "list")
    state["keywords"][state["keywords_pos"]]++;

  # If the outer collection is an array, remove the keyword that
  # routed to the collection we just popped.
  else
    state["keywords"][state["keywords_pos"]--] = NULL;

  # For safety, be sure we've not popped the outermost, implicit list.
  #
  # The base of the types list is:
  #   [ "list" ]
  #
  # The base of the keywords list is:
  #   [ <result path>, <result path index> ].
  if (state["types_pos"] < 0 || state["keywords_pos"] < 1)
    exit(1, "Illegal operation in unpack(): unmatched '" + state["operator"] + "'.");

  return state;
}

##
# A private helper function for unpack().
#
# This is called when we're finished reading the current operator and
# modifiers in the format string, and we're ready to process zero or
# more bytes of data. The name of the state is _PACK_STATE_READY.
#
# This doesn't process any bytes in the format string, but instead
# processes bytes in the data as required. This always sets the state
# back to _PACK_STATE_READY, unless we're out of data to process, in
# which case it goes to _PACK_STATE_DONE.
#
# @param state The state object.
# @param c     The current character in the format string.
#
# @return The new state object.
##
function _unpack_handle_state_ready(c, data, state)
{
  local_var add_tmp_after_loop, data_len, j, order, str, tmp;

  # Start tmp as the empty string since certain operators (like 'a*')
  # accumulate characters
  tmp = "";
  add_tmp_after_loop = FALSE;
  data_len = strlen(data);

  # Handle the '@' operator specially. This has to be done to avoid
  # adding a blank string to the array if the usual loop doesn't
  # happen.
  #
  # '@' moves to the indicated offset.
  if (state["operator"] == "@")
  {
    if (state["count"] == "*")
      exit(1, "Illegal operator in unpack(): '@*' is an invalid combination.");

    state["data_pos"] = state["count"];
    tmp = NULL;
  }

  # This loop processes the appropriate number of characters from the
  # data string, putting them - properly formatted - in the variable
  # 'tmp' and incrementing the 'data_pos' offset the proper amount.
  #
  # In the case of the '*' modifier, we loop to the end of the data
  # rather than a specified number of bytes (except in the case of 'Z'
  # where the loop terminates at a '\0').
  for (j = 0; j < state["count"] || (state["count"] == "*" && state["data_pos"] < data_len); j++)
  {
    ##################################################################
    # 8-bit Integers
    ##################################################################

    # 8-bit integers.
    if (state["operator"] =~ "[cC]")
    {
      # Verify the length.
      if (state["data_pos"] + 1 > data_len)
        return NULL;

      tmp = getbyte(blob:data, pos:state["data_pos"]);

      # To convert an unsigned to signed in two's complement, you
      # invert and add one.
      if (state["operator"] == "c" && (tmp & 0x80))
        tmp = -((~tmp + 1) & 0xFF);

      state["data_pos"]++;
    }

    ##################################################################
    # 16-bit Integers
    ##################################################################

    # 16-bit integers (endian implicit).
    else if (state["operator"] =~ "[sS]")
    {
      # Verify the length.
      if (state["data_pos"] + 2 > data_len)
        return NULL;

      tmp = getword(blob:data, pos:state["data_pos"], order:state["byte_order"]);

      # To convert an unsigned to signed in two's complement, you
      # invert and add one.
      if (state["operator"] == "s" && (tmp & 0x8000))
        tmp = -((~tmp + 1) & 0xFFFF);

      state["data_pos"] += 2;
    }

    # 16-bit unsigned integers (endian explicit).
    else if (state["operator"] =~ "[nv]")
    {
      # Verify the length.
      if (state["data_pos"] + 2 > data_len)
        return NULL;

      if (state["operator"] == "n")
        order = BYTE_ORDER_BIG_ENDIAN;
      else
        order = BYTE_ORDER_LITTLE_ENDIAN;

      tmp = getword(blob:data, pos:state["data_pos"], order:order);

      state["data_pos"] += 2;
    }

    ##################################################################
    # 24-bit Integers
    ##################################################################

    # 24-bit integer (non-standard).
    else if (state["operator"] =~ "[tT]")
    {
      # Verify the length.
      if (state["data_pos"] + 3 > data_len)
        return NULL;

      if (state["byte_order"] == BYTE_ORDER_LITTLE_ENDIAN)
      {
        tmp = int(getbyte(blob:data, pos:state["data_pos"] + 0)) <<  0 |
              int(getbyte(blob:data, pos:state["data_pos"] + 1)) <<  8 |
              int(getbyte(blob:data, pos:state["data_pos"] + 2)) << 16;
      }
      else
      {
        tmp = int(getbyte(blob:data, pos:state["data_pos"] + 0)) << 16 |
              int(getbyte(blob:data, pos:state["data_pos"] + 1)) <<  8 |
              int(getbyte(blob:data, pos:state["data_pos"] + 2)) <<  0;
      }

      # To convert an unsigned to signed in two's complement, you
      # invert and add one.
      if (state["operator"] == "t" && (tmp & 0x800000))
        tmp = -((~tmp + 1) & 0xFFFFFF);

      state["data_pos"] += 3;
    }

    ##################################################################
    # 32-bit Integers
    ##################################################################

    # Signed 32-bit integer.
    else if (state["operator"] == "l")
    {
      # Verify the length.
      if (state["data_pos"] + 4 > data_len)
        return NULL;

      tmp = getdword(blob:data, pos:state["data_pos"], order:state["byte_order"]);

      state["data_pos"] += 4;
    }

    # Unsigned 32-bit integer.
    else if (state["operator"] == "L")
    {
      # Verify the length.
      if (state["data_pos"] + 4 > data_len)
        return NULL;

      # We need to do this manually since otherwise we'll get a signed
      # 32-bit integer.
      if (state["byte_order"] == BYTE_ORDER_LITTLE_ENDIAN)
      {
        tmp = uint(getbyte(blob:data, pos:state["data_pos"] + 0)) <<  0 |
              uint(getbyte(blob:data, pos:state["data_pos"] + 1)) <<  8 |
              uint(getbyte(blob:data, pos:state["data_pos"] + 2)) << 16 |
              uint(getbyte(blob:data, pos:state["data_pos"] + 3)) << 24;
      }
      else
      {
        tmp = uint(getbyte(blob:data, pos:state["data_pos"] + 0)) << 24 |
              uint(getbyte(blob:data, pos:state["data_pos"] + 1)) << 16 |
              uint(getbyte(blob:data, pos:state["data_pos"] + 2)) <<  8 |
              uint(getbyte(blob:data, pos:state["data_pos"] + 3)) <<  0;
      }

      state["data_pos"] += 4;
    }

    # 32-bit unsigned big endian integer.
    else if (state["operator"] == "N")
    {
      # Verify the length.
      if (state["data_pos"] + 4 > data_len)
        return NULL;

      # We need to do this manually since otherwise we'll get a signed
      # 32-bit integer.
      tmp = uint(getbyte(blob:data, pos:state["data_pos"] + 0)) << 24 |
            uint(getbyte(blob:data, pos:state["data_pos"] + 1)) << 16 |
            uint(getbyte(blob:data, pos:state["data_pos"] + 2)) <<  8 |
            uint(getbyte(blob:data, pos:state["data_pos"] + 3)) <<  0;

      state["data_pos"] += 4;
    }

    # 32-bit unsigned little endian integer.
    else if (state["operator"] == "V")
    {
      # Verify the length.
      if (state["data_pos"] + 4 > data_len)
        return NULL;

      # We need to do this manually since otherwise we'll get a signed
      # 32-bit integer.
      tmp = uint(getbyte(blob:data, pos:state["data_pos"] + 0)) <<  0 |
            uint(getbyte(blob:data, pos:state["data_pos"] + 1)) <<  8 |
            uint(getbyte(blob:data, pos:state["data_pos"] + 2)) << 16 |
            uint(getbyte(blob:data, pos:state["data_pos"] + 3)) << 24;

      state["data_pos"] += 4;
    }

    ##################################################################
    # 64-bit Integers
    ##################################################################

    # Signed 64-bit integer (not supported).
    else if (state["operator"] == "q")
    {
      exit(1, "Illegal operator in unpack() - 64-bit values are not supported.");
    }

    # Unsigned 64-bit integer (not supported).
    else if (state["operator"] == "Q")
    {
      exit(1, "Illegal operator in unpack() - 64-bit values are not supported.");
    }

    ##################################################################
    # Strings
    ##################################################################

    # ASCII string.
    else if (state["operator"] =~ "[aA]")
    {
      add_tmp_after_loop = TRUE;

      tmp += data[state["data_pos"]++];
    }

    # NUL-terminated string.
    else if (state["operator"] == "Z")
    {
      add_tmp_after_loop = TRUE;

      # Break at a NUL if we're on a '*' but not otherwise.
      if (state["count"] == "*" && data[state["data_pos"]] == '\0')
      {
        state["data_pos"]++;
        break;
      }

      tmp += data[state["data_pos"]++];
    }

    # Binary string.
    else if (state["operator"] =~ "[bB]")
    {
      add_tmp_after_loop = TRUE;

      tmp += data[state["data_pos"]++];

      # Each entry is made up of 8 characters, so we need to increment
      # count faster.
      j += 7;
    }

    # Hex string.
    else if (state["operator"] =~ "[hH]")
    {
      add_tmp_after_loop = TRUE;

      tmp += data[state["data_pos"]++];

      # Each entry is made up of 2 characters, so we need to increment
      # count faster.
      j++;
    }

    ##################################################################
    # Movement
    ##################################################################

    # Move forward one byte.
    else if (state["operator"] == "x")
    {
      state["data_pos"]++;

      # Don't add this to the string.
      tmp = NULL;
    }

    # Move backwards one byte.
    else if (state["operator"] == "X")
    {
      state["data_pos"]--;

      # Don't add this to the string.
      tmp = NULL;
    }

    # Jump to location.
    else if (state["operator"] == "@")
    {
      # This is handled elsewhere
    }

    ##################################################################
    # Collections
    ##################################################################

    # List (non-standard).
    else if (state["operator"] =~ "[[\]]")
    {
      add_tmp_after_loop = TRUE;

      # Don't add this to the string.
      tmp = NULL;
    }

    # Array (non-standard).
    else if (state["operator"] =~ "[{}]")
    {
      add_tmp_after_loop = TRUE;

      # Don't add this to the string.
      tmp = NULL;
    }

    ##################################################################
    # Dynamic Counts
    ##################################################################

    # Fetch Count.
    else if (state["operator"] == "?")
    {
      # Fetch the count from the results and make it ready for use by
      # a future operator.
      state["dynamic_count"] = path_get(args:state["count_keywords"]);

      # Don't add this to the string.
      tmp = NULL;
    }

    ##################################################################
    # Unsupported
    ##################################################################

    # UTF-8 string (not supported).
    else if (state["operator"] == "U")
    {
      exit(1, "Illegal operator in unpack() - UTF-8 is not supported.");
    }

    # BER integer (not supported).
    else if (state["operator"] == "w")
    {
      exit(1, "Illegal operator in unpack() - BER integers are not supported.");
    }

    # Floating point (not supported).
    else if (state["operator"] =~ "[dDfFeEgG]")
    {
      exit(1, "Illegal operator in unpack() - floating point is not supported.");
    }

    # Base64 and MIME (not supported).
    else if (state["operator"] =~ "[umM]")
    {
      exit(1, "Illegal operator in unpack() - base64 and MIME encoding not implemented.");
    }

    # Pointers (not supported).
    else if (state["operator"] =~ "[pP]")
    {
      exit(1, "Illegal operator in unpack() - pointers not implemented.");
    }

    else
    {
      exit(1, "Illegal operator in unpack() - '" + state["operator"] + "'.");
    }

    if (!add_tmp_after_loop && !isnull(tmp))
      state = _unpack_add(state:state, data:tmp);
  }

  # The operator 'A' strips off trailing NULs.
  if (state["operator"] == "A")
  {
    while (strlen(tmp) > 0 && right(tmp, 1) == '\0')
      tmp = left(tmp, strlen(tmp) - 1);
  }

  # The operator 'Z' terminates at NUL.
  else if (state["operator"] == "Z")
  {
    if (strstr(tmp, '\0'))
      tmp = left(tmp, strlen(tmp) - strlen(strstr(tmp, '\0')));
  }

  # The operators 'b' and 'B' do binary strings.
  else if (state["operator"] =~ "[bB]")
  {
    str = "";

    # Loop through the string and convert the bits to binary.
    for (j = 0; j < strlen(tmp); j++)
    {
      # LSB first.
      if (state["operator"] == "b")
        str += ltostr(ord(tmp[j]), base:2, precision:8, lsb_first:TRUE);

      # MSB first.
      else
        str += ltostr(ord(tmp[j]), base:2, precision:8, lsb_first:FALSE);
    }

    tmp = str;
    if (state["count"] != "*")
      tmp = left(str, state["count"]);
  }

  # The operators 'h' and 'H' do hex strings.
  else if (state["operator"] =~ "[hH]")
  {
    str = "";

    # Loop through the string and convert the nibbles to hex.
    for (j = 0; j < strlen(tmp); j++)
    {
      # LSN first.
      if (state["operator"] == "h")
        str += byte_to_hex(ord(tmp[j]), lsn_first:TRUE);

      # MSN first.
      else
        str += byte_to_hex(ord(tmp[j]), lsn_first:FALSE);
    }

    tmp = str;
    if (state["count"] != "*")
      tmp = left(tmp, state["count"]);
  }

  # The operators '[' and ']' create lists.
  else if (state["operator"] == "[")
  {
    tmp = make_list();
  }
  else if (state["operator"] == "]")
  {
    state = _unpack_pop(state:state);
    tmp = NULL;
  }

  # The operators '{' and '}' create arrays.
  else if (state["operator"] == "{")
  {
    tmp = make_array();
  }
  else if (state["operator"] == "}")
  {
    state = _unpack_pop(state:state);
    tmp = NULL;
  }

  if (add_tmp_after_loop && !isnull(tmp))
    state = _unpack_add(state:state, data:tmp);

  # Reset variables to default.
  state = _pack_reset_state(state:state);

  # Check for the end of the input.
  if (isnull(c))
    state["state"] = _PACK_STATE_DONE;

  # Return the state.
  return state;
}

##
# A private helper function for pack().
#
# This is called when we're finished reading the current operator and
# modifiers in the format string, and we're ready to process 0 or more
# args.  The name of the state is _PACK_STATE_READY.
#
# This doesn't process any bytes in the format string, but instead
# processes bytes in the data as required. This always sets the state
# back to _PACK_STATE_READY, unless we're out of arguments to process,
# in which case it goes to _PACK_STATE_DONE.
#
# @param args  The array of arguments.
# @param c     The current character - used to detect if we're at the end of
#              the string.
# @param state The state object.
#
# @return The new state object.
##
function _pack_handle_state_ready(args, c, state)
{
  local_var i, j, increment_pos_after, operator, tmp, tmp_bin, tmp_hex, tmp_pos;

  # Start tmp as the empty string since certain operators (like 'a*')
  # require their own temporary state
  increment_pos_after = FALSE;
  tmp_pos = 0;

  for (j = 0; j < state["count"] || state["count"] == "*"; j++)
  {
    # Choose what data to use for the current operator.
    if (max_index(state["keywords"]) > 1)
    {
      tmp = path_get(args:state["keywords"]);
    }
    else if (state["args_pos"] < max_index(args))
    {
      tmp = args[state["args_pos"]];
    }
    else
    {
      break;
    }

    ##################################################################
    # 8-bit Integers
    ##################################################################

    # 8-bit integer.
    if (state["operator"] =~ "[cC]")
    {
      state["result"] = state["result"] + mkbyte(int(tmp));

      if (max_index(state["keywords"]) <= 1)
        state["args_pos"]++;
    }

    ##################################################################
    # 16-bit Integers
    ##################################################################

    # 16-bit integer.
    else if (state["operator"] =~ "[sS]")
    {
      state["result"] += mkword(int(tmp), order:state["byte_order"]);

      if (max_index(state["keywords"]) <= 1)
        state["args_pos"]++;
    }

    # 16-bit unsigned big endian integer.
    else if (state["operator"] == "n")
    {
      state["result"] += mkword(int(tmp), order:BYTE_ORDER_BIG_ENDIAN);

      if (max_index(state["keywords"]) <= 1)
        state["args_pos"]++;
    }

    # 16-bit unsigned little endian integer.
    else if (state["operator"] == "v")
    {
      state["result"] += mkword(int(tmp), order:BYTE_ORDER_LITTLE_ENDIAN);

      if (max_index(state["keywords"]) <= 1)
        state["args_pos"]++;
    }

    ##################################################################
    # 24-bit Integers
    ##################################################################

    # 24-bit integer (non-standard).
    else if (state["operator"] =~ "[tT]")
    {
      tmp = int(tmp);
      if (state["byte_order"] == BYTE_ORDER_BIG_ENDIAN)
      {
        state["result"] +=
          mkbyte((tmp >> 16) & 0x0000FF) +
          mkbyte((tmp >>  8) & 0x0000FF) +
          mkbyte((tmp >>  0) & 0x0000FF);
      }
      else
      {
        state["result"] +=
          mkbyte((tmp >>  0) & 0x0000FF) +
          mkbyte((tmp >>  8) & 0x0000FF) +
          mkbyte((tmp >> 16) & 0x0000FF);
      }

      tmp = "";

      if (max_index(state["keywords"]) <= 1)
        state["args_pos"]++;
    }

    ##################################################################
    # 32-bit Integers
    ##################################################################

    # 32-bit integer.
    else if (state["operator"] =~ "[lL]")
    {
      state["result"] += mkdword(int(tmp), order:state["byte_order"]);

      if (max_index(state["keywords"]) <= 1)
        state["args_pos"]++;
    }

    # 32-bit unsigned big endian integer.
    else if (state["operator"] == "N")
    {
      state["result"] += mkdword(int(tmp), order:BYTE_ORDER_BIG_ENDIAN);

      if (max_index(state["keywords"]) <= 1)
        state["args_pos"]++;
    }

    # 32-bit unsigned little endian integer.
    else if (state["operator"] == "V")
    {
      state["result"] += mkdword(int(tmp), order:BYTE_ORDER_LITTLE_ENDIAN);

      if (max_index(state["keywords"]) <= 1)
        state["args_pos"]++;
    }

    ##################################################################
    # 64-bit Integers
    ##################################################################

    # 64-bit integers.
    else if (state["operator"] =~ "[qQ]")
    {
      exit(1, "Illegal operator in pack() - 64-bit values are not supported.");
    }

    ##################################################################
    # Strings
    ##################################################################

    # ASCII space/NUL-padded string.
    else if (state["operator"] =~ "[aA]")
    {
      increment_pos_after = TRUE;

      # If the position is part of the string, add it as normal.
      if (tmp_pos < strlen(tmp))
        state["result"] = state["result"] + tmp[tmp_pos];

      # If the count isn't 'rest of the string', pad with spaces.
      else if (state["count"] != "*")
      {
        if (state["operator"] == "a")
          state["result"] += '\0';
        else
          state["result"] += " ";
      }

      # If the count is 'rest of the string', and we're at the end of
      # the string, break.
      else
        break;

      tmp_pos++;
    }

    # NUL-terminated string.
    else if (state["operator"] == "Z")
    {
      increment_pos_after = TRUE;

      # If the position is part of the string, add it as normal.
      if (tmp_pos < strlen(tmp))
        state["result"] += tmp[tmp_pos];

      # If the count isn't 'rest of the string', pad with NULs.
      else if (state["count"] != "*")
        state["result"] += '\0';

      # If the count is 'rest of the string', and we're at the end of
      # the string, add a NUL and break.
      else
      {
        state["result"] += '\0';
        break;
      }

      tmp_pos++;
    }

    # Binary string.
    else if (state["operator"] =~ "[bB]")
    {
      increment_pos_after = TRUE;

      tmp_bin = "";
      for (i = j; i < j + 8; i++)
      {
        if (i < strlen(tmp) && (state["count"] == "*" || i < state["count"]))
        {
          if (state["operator"] == "B")
            tmp_bin = tmp_bin + tmp[i];
          else
            tmp_bin = tmp[i] + tmp_bin;
        }
        else
        {
          if (state["operator"] == "B")
            tmp_bin = tmp_bin + "0";
          else
            tmp_bin = "0" + tmp_bin;
        }
      }
      state["result"] += mkbyte(strtol(tmp_bin, base:2));

      # Increment the location faster
      j += 7;

      # Check if we're reading the whole string and we're done
      if (state["count"] == "*" && j >= strlen(tmp) - 1)
        break;
    }

    # Hex string.
    else if (state["operator"] =~ "[hH]")
    {
      increment_pos_after = TRUE;

      tmp_hex = "";
      for (i = j; i < j + 2; i++)
      {
        if (i < strlen(tmp) && (state["count"] == "*" || i < state["count"]))
        {
          if (state["operator"] == "H")
            tmp_hex = tmp_hex + tmp[i];
          else
            tmp_hex = tmp[i] + tmp_hex;
        }
        else
        {
          if (state["operator"] == "H")
            tmp_hex = tmp_hex + "0";
          else
            tmp_hex = "0" + tmp_hex;
        }
      }
      state["result"] += mkbyte(strtol(tmp_hex, base:16));

      # Increment the location faster
      j += 1;

      # Check if we're reading the whole string and we're done
      if (state["count"] == "*" && j >= strlen(tmp) - 1)
        break;
    }

    ##################################################################
    # Movement
    ##################################################################

    # Move forward one byte.
    else if (state["operator"] == "x")
    {
      state["result"] += crap(data:'\0', length:state["count"]);
      break;
    }

    # Move backwards one byte.
    else if (state["operator"] == "X")
    {
      state["result"] = left(state["result"], strlen(state["result"]) - state["count"]);
      break;
    }

    # Jump to location.
    else if (state["operator"] == "@")
    {
      if (state["count"] == "*")
        exit(1, "Illegal operator in pack(): '@*' is an invalid combination");

      if (state["count"] < strlen(state["result"]))
        state["result"] = left(state["result"], state["count"]);
      else if (state["count"] > strlen(state["result"]))
        state["result"] += crap(length:(state["count"] - strlen(state["result"])), data:'\0');

      break;
    }

    ##################################################################
    # Unsupported
    ##################################################################

    # UTF-8 string (not supported).
    else if (state["operator"] == "U")
    {
      exit(1, "Illegal operator in pack() - UTF-8 is not supported.");
    }

    # BER integer (not supported).
    else if (state["operator"] == "w")
    {
      exit(1, "Illegal operator in pack() - BER integers are not supported.");
    }

    # Floating point (not supported).
    else if (state["operator"] =~ "[dDeEfFgG]")
    {
      exit(1, "Illegal operator in pack() - floating point is not supported.");
    }

    # Base64 and MIME (not supported).
    else if (state["operator"] =~ "[umM]")
    {
      exit(1, "Illegal operator in pack() - base64 and MIME encoding not implemented.");
    }

    # Pointers (not supported).
    else if (state["operator"] =~ "[pP]")
    {
      exit(1, "Illegal operator in pack() - pointers not implemented.");
    }

    else
    {
      exit(1, "Illegal operator in pack() - '" + state["operator"] + "'.");
    }
  }

  # Certain operators (e.g., the string ones) don't increment their
  # position until after they're done.
  if (increment_pos_after && max_index(state["keywords"]) <= 1)
    state["args_pos"]++;

  # Reset variables to default.
  state = _pack_reset_state(state:state);

  # Check for the end of the packet
  if (isnull(c))
    state["state"] = _PACK_STATE_DONE;

  # Return the state
  return state;
}

##
# Take a string - data - and convert it into an array based on the
# format string given in the format argument.
#
# The output of this is intentionally based on ruby's String#unpack
# function as much as possible. Not all operators are implemented,
# though - unimplemented operators will exit with an error message,
# which tells the developer they should fix the problem.
#
# The format string consists of an operator followed by a optional
# modifiers.
#
# By default, all operators are network byte order (big endian),
# unless the '<' modifier is used (or the operator specifically says
# it uses little endian ('v' and 'V', for example, are always little
# endian).
#
# To add additional structure to the result, a collection can be
# declared using the '[' and '{' operators. '[' begins a list, while
# '{' begins an array. Arrays must have a keyword attached to each
# operator.
#
# Operators:
#
#   C - 8-bit  unsigned integer
#   S - 16-bit unsigned integer
#   T - 24-bit unsigned integer
#   L - 32-bit unsigned integer
#   Q - 64-bit unsigned integer (not implemented)
#
#   c - 8-bit  signed integer
#   s - 16-bit signed integer
#   t - 24-bit signed integer
#   l - 32-bit signed integer
#   q - 64-bit signed integer (not implemented)
#
#   n - 16-bit unsigned big-endian integer
#   N - 32-bit unsigned big-endian integer
#   v - 16-bit unsigned little-endian integer
#   V - 32-bit unsigned little-endian integer
#
#   A - arbitrary binary string (with trailing NULLs removed)
#   a - arbitrary binary string
#   Z - null-terminated string
#   B - binary string (MSB first)
#   b - binary string (LSB first)
#   H - hex string (high nibble first)
#   h - hex string (low nibble first)
#
#   @ - skip to offset <count>
#   X - skip backward <count> bytes
#   x - skip forward <count> bytes
#
#   [ - start a list
#   ] - end the current list
#   { - start an array
#   } - end the current array
#
#   ? - retrieve dynamic count
#
#   U - UTF-8 character (not implemented)
#   w - BER-compressed integer (not implemented)
#   D, d, F, f, E, e, G, g - floating point (not implemented)
#   u - uuencoded string (not implemented)
#   M - MIME-encoded string (not implemented)
#   m - base64-encoded string (not implemented)
#   P, p - pointer to a structure (not implemented)
#
#
# Modifiers:
#
#   * - assume infinite count
#   # - use retrieved item as count
#   < - little endian
#   > - big endian
#   ! - native endian (not implemented)
#   ( - keyword
#
# Examples:
#
#   unpack('C*', '\x01\x23\x45\x67')                   => [ 0x01, 0x23, 0x45, 0x67 ]
#   unpack('xax2aX2aX1aX2a', 'whole')                  => [ 'h', 'e', 'l', 'l', 'o' ]
#   unpack('b8B8', 'aa')                               => [ '10000110', '01100001' ]
#   unpack('h2H2c', 'aaa')                             => [ 16, 61, 97 ]
#   unpack('Z6Z*', 'test\0test2\0')                    => [ 'test', 'est2' ]
#   unpack('a3a3a3a*', 'abc \0\0\0\0\0Hello World!\0') => [ 'abc', ' \0\0', '\0\0\0', 'Hello World!\0' ]
#   unpack('A3A3A3A*', 'abc \0\0\0\0\0Hello World!\0') => [ 'abc', ' ',     '',       'Hello World!'   ]
#   unpack('[C]', '\x07')                              => [ [ 7 ] ]
#   unpack('[C][C]', '\x07\x08')                       => [ [ 7 ], [ 8 ] ]
#   unpack('C{a(b2)}', '\x07ABC')                      => [ 7, { 'b2' : 'ABC' } ]
#   unpack('C{(b1){a(b2)}}', '\x07ABC')                => [ 7, { 'b1' : { 'b2' : 'ABC' } } ]
#   unpack('C ?(0) a#', '\x07monkeys')                 => [ 7, 'monkeys' ]
#
# @anonparam format The format string indicating how to parse the string
# @anonparam data   The string to parse.
#
# @return A list of the parsed data.
##
function unpack()
{
  local_var c, data, format, j, res, state;

  # Check the arguments.
  if (max_index(_FCT_ANON_ARGS) != 2)
    return NULL;

  format = _FCT_ANON_ARGS[0];
  data = _FCT_ANON_ARGS[1];

  # Initialize the state.
  state = make_array(
    "data_pos", 0,
    "dynamic_count", NULL,
    "format_pos", 0,
    "function", "unpack",
    "keywords_pos", 1,
    "types_pos", 0
  );

  state["result"] = path_store(make_list());
  state["types"] = make_list("list");

  # Set up the keywords.
  state["keywords"] = make_list();
  state["keywords"][0] = state["result"];
  state["keywords"][1] = 0;

  # Reset the temporary variables.
  state = _pack_reset_state(state:state);

  # This loops over the format string, taking each letter/number and
  # processing it in a state machine.
  while (state["state"] != _PACK_STATE_DONE)
  {
    # Check for errors.
    if (isnull(state))
      return NULL;

    if (state["format_pos"] < strlen(format))
      c = format[state["format_pos"]];
    else
      c = NULL;

    # Ignore spaces.
    if (c =~ "\s")
    {
      state["format_pos"]++;
      continue;
    }

    # This is a simple state machine with five states:
    # 1. _PACK_STATE_NEW - reading the operator
    # 2. _PACK_STATE_HAVE_OPERATOR - reading modifiers (if any)
    # 3. _PACK_STATE_KEYWORD - reading keywords
    # 4. _PACK_STATE_READY - go ahead and parse the packet
    # 5. _PACK_STATE_DONE - we're finished, and can return
    if (state["state"] == _PACK_STATE_NEW)
      state = _pack_handle_state_new(state:state, c:c);
    else if (state["state"] == _PACK_STATE_HAVE_OPERATOR)
      state = _pack_handle_state_have_operator(state:state, c:c);
    else if (state["state"] == _PACK_STATE_KEYWORD)
      state = _pack_handle_state_keyword(state:state, c:c);
    else if (state["state"] == _PACK_STATE_READY)
      state = _unpack_handle_state_ready(state:state, c:c, data:data);
    else
      exit(1, "unpack() reached an illegal state.");
  }

  # Clean up.
  res = path_get(state["result"]);
  path_free(state["result"]);

  return res;
}

##
# Take an an array - args - and convert it into a string based on the
# format string given in the format argument.
#
# The output of this is intentionally based on ruby's String#pack
# function as much as possible. Not all operators are implemented,
# though - unimplemented operators will exit with an error message,
# which tells the developer they should fix the problem.
#
# The format string consists of an operator followed by a optional
# modifiers.
#
# By default, all operators are network byte order (big endian),
# unless the '<' modifier is used (or the operator specifically says
# it uses little endian ('v' and 'V', for example, are always little
# endian).
#
# If the 'kw' argument is given, keywords can be used to index into
# the data structure passed.
#
# Operators:
#
#   C - 8-bit  unsigned integer
#   S - 16-bit unsigned integer
#   T - 24-bit unsigned integer
#   L - 32-bit unsigned integer
#   Q - 64-bit unsigned integer (not implemented)
#
#   c - 8-bit  signed integer
#   s - 16-bit signed integer
#   t - 24-bit signed integer
#   l - 32-bit signed integer
#   q - 64-bit signed integer (not implemented)
#
#   n - 16-bit unsigned big-endian integer
#   N - 32-bit unsigned big-endian integer
#   v - 16-bit unsigned little-endian integer
#   V - 32-bit unsigned little-endian integer
#
#   A - arbitrary binary string (with trailing NULLs removed)
#   a - arbitrary binary string
#   Z - null-terminated string
#   B - binary string (MSB first)
#   b - binary string (LSB first)
#   H - hex string (high nibble first)
#   h - hex string (low nibble first)
#
#   @ - skip to offset <count>
#   X - skip backward <count> bytes
#   x - skip forward <count> bytes
#
#   U - UTF-8 character (not implemented)
#   w - BER-compressed integer (not implemented)
#   D, d, F, f, E, e, G, g - floating point (not implemented)
#   u - uuencoded string (not implemented)
#   M - MIME-encoded string (not implemented)
#   m - base64-encoded string (not implemented)
#   P, p - pointer to a structure (not implemented)
#
# Modifiers:
#
#   * - assume infinite count
#   < - little endian
#   > - big endian
#   ! - native endian (not implemented)
#   ( - keyword
#
# Examples:
#
#   pack(format:"s<s>l<l>",        args:make_list(0x1234, 0x1234, 0x12345678, 0x12345678)) => '\x34\x12\x12\x34\x78\x56\x34\x12\x12\x34\x56\x78'
#   pack(format:'nNvV',            args:make_list(0x1234, 0x12345678, 0x1234, 0x12345678)) => '\x12\x34\x12\x34\x56\x78\x34\x12\x78\x56\x34\x12'
#   pack(format:"ttt<t>",          args:make_list(-1, 0xFFFFFF, 0x123456, 0x123456))       => '\xff\xff\xff\xff\xff\xff\x56\x34\x12\x12\x34\x56'
#   pack(format:'a',               args:make_list('ABC', 'DEF'))                           => 'A'
#   pack(format:'a*',              args:make_list('ABC', 'DEF'))                           => 'ABC'
#   pack(format:'a*Z*',            args:make_list('ABC', 'DEF'))                           => 'ABCDEF\0'
#   pack(format:'Z5Z*Z5',          args:make_list('ABC', 'DEF', 'GHI'))                    => 'ABC\0\0DEF\0GHI\0\0'
#   pack(format:'c@4cx10ccX4c@4c', args:make_list(0x41, 0x42, 0x43, 0x44, 0x45, 0x46))     => 'A\0\0\0F'
#   pack('a*(1)(b2)Z*', 'DEF', kw:[7, {"b2":"ABC"}])                                       => 'ABCDEF\0'
#
# @param args   The array to build the string out of.
# @param format The format string indicating how to build the string.
# @param kw     The list of keyword arguments.
#
# @return The final string.
##
function pack(args, format, kw)
{
  local_var c, j, state;

  # Initialize the state.
  state = make_array(
    "args_pos", 0,
    "format_pos", 0,
    "function", "pack",
    "result", ""
  );

  # Store the keywords using the path library, to guard against making
  # repeated copies of data in the event of a large data structure
  # being passed in.
  if (!isnull(kw))
    state["kw"] = path_store(kw);

  # Reset the temporary variables.
  state = _pack_reset_state(state:state);

  # If there were no named args were passed, use the anonymous ones.
  if (isnull(args))
    args = _FCT_ANON_ARGS;

  # If there was no format passed in, and args is not empty, assume
  # that the first element of args is the format. If there's no first
  # element, error out.
  if (isnull(format))
  {
    if (max_index(args) == 0)
      exit(1, "pack was not implicitly nor explicitly given a format.");

    format = args[0];
    state["args_pos"] = 1;
  }

  # This loops over the format string, taking each letter/number and
  # processing it in a state machine.
  while (state["state"] != _PACK_STATE_DONE)
  {
    # Check for errors.
    if (isnull(state))
      return NULL;

    if (state["format_pos"] < strlen(format))
      c = format[state["format_pos"]];
    else
      c = NULL;

    # Ignore spaces.
    if (c =~ "\s")
    {
      state["format_pos"]++;
      continue;
    }

    # This is a simple state machine with five states:
    # 1. _PACK_STATE_NEW - reading the operator
    # 2. _PACK_STATE_HAVE_OPERATOR - reading modifiers (if any)
    # 3. _PACK_STATE_KEYWORD - reading keywords
    # 4. _PACK_STATE_READY - go ahead and parse the packet
    # 5. _PACK_STATE_DONE - we're finished, and can return
    if (state["state"] == _PACK_STATE_NEW)
      state = _pack_handle_state_new(state:state, c:c);
    else if (state["state"] == _PACK_STATE_HAVE_OPERATOR)
      state = _pack_handle_state_have_operator(state:state, c:c);
    else if (state["state"] == _PACK_STATE_KEYWORD)
      state = _pack_handle_state_keyword(state:state, c:c);
    else if (state["state"] == _PACK_STATE_READY)
      state = _pack_handle_state_ready(state:state, c:c, args:args);
    else
      return NULL;
  }

  # Free the keywords stored in the path library.
  if (!isnull(kw))
    path_free(state["kw"]);

  return state["result"];
}
