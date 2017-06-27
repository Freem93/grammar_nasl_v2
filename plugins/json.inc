#TRUSTED 7431ae1d1187634b7921108c758b90c09494e404075e00451659164b4cb2d6689973f2e5ef6f98970cf1bc467c3070056235df4bfa25dccb295da55a08c7de02c5a4ea13020f5e96408d5acf1957b46a8cccd36c1b4c3dfe3623c68daa33f59193b300f1fdf3fcb20850dbd303701d6c1110b6daaac5221aab390bd041202731d457281ccbe35a81660d102bdfca0e357abde163fef03d0769f669946cd66d56bfcc7922eaf30dda3a1ccc2f9e107c0a5465f71ce0a0082367ebd379910f9b890402828f07c8784e331e706ac1332c8da6cc4e6047083c0cdfc9e34267c5a4703b881936e3de910f31f0901aadf323a41dfb2f8602192d04f8f0fecdf5902318d0809861fe9639d390ede863cec9fb702c217bb60b221e7b073f7fb993a9f5f19bffde156cd2078c40bb52e6e8d27f381b16886f4ebeb5ad4587796c893a42983d2b21d730406af8daf0d6beef15d89b01b2c22a38681663a84e409efd50081c1deb08de2def8bebd5b4f78ab9957291faad476a8407ea1235b6c7673e873c95c6bea6dd5806235c79140ef73514463783718c9a8e88ba8c06a03185865c2c819d7ad9272452927f53a85cc5238e806ff1c1ff711e053cde17ee900d5332ade7bfecf16aa95cf2a2150dafa956fbe65dacf3b63a61eb416a14471b23d6463d651b221ec54621953c096c96e060e14a593090d1fab7e03b25ca84cc991143e531
#
# (C) Tenable Network Security, Inc.
#
# @NOGPL@
#
# Revision: 1.3
#
# @include misc_func.inc
# @include path.inc
###

######################################################################
# Private Helper Functions
######################################################################

##
# Creates a list containing the results of parsing a token.
#
# This function is used to ensure that if an array or list is returned
# as the result of parsing a token, it is never flattened.
#
# @anonparam ds The NASL data structure the token represented.
# @anonparam blob The unparsed remainder of the blob.
#
# @return A list containing all the passed parameters.
##
function _success()
{
  local_var i, res;

  res = make_list();
  for (i = 0; i < max_index(_FCT_ANON_ARGS); i++)
  {
    res[i] = _FCT_ANON_ARGS[i];
  }

  return res;
}

##
# Creates a list containing an error message from a failed parse.
#
# Since parsing functions should always return lists, and those lists
# can contain any value, no value on its own can signify an error. So
# errors are represented by a NULL where the blob is expected.
#
# @anonparam msg A string containing the error message.
# @anonparam blob A string containing the JSON.
#
# @return A list containing an error message.
##
function _error()
{
  local_var blob, msg;

  msg = _FCT_ANON_ARGS[0];
  blob = _FCT_ANON_ARGS[1];

  # Include a sample of the blob at the point where the error
  # occurred.
  if (!isnull(blob))
    msg += " at : " + substr(blob, 0, 19);

  return make_nested_list(msg, NULL);
}

##
# Determines whether the passed NASL object is an array or a list.
#
# @anonparam ds A data structure.
#
# @return TRUE if the object is a list, FALSE otherwise.
##
function _is_list()
{
  local_var ds, k, ks;

  ds = _FCT_ANON_ARGS[0];
  ks = path_keys(ds);

  # Lists appear to the typeof function as arrays.
  if (typeof(ds) != "array")
      return FALSE;

  # If the data structure is empty, we can't base our decision on its
  # keys. So we use the fact that max_index() always returns the same
  # value for arrays.
  if (max_index(ks) <= 0 && max_index(ds) == 3)
    return FALSE;

  # A non-empty list will have a number of keys, each of which are
  # integers. If any key in the list is not an integer, the data
  # structure is an array.
  foreach k (ks)
  {
    # A list contains keys that are only integers.
    if (typeof(k) != "int")
      return FALSE;
  }

  return TRUE;
}

##
# Removes leading whitespace from a string.
#
# @anonparam blob A string in JSON format.
#
# @return A string with no leading whitespace.
##
function _trim()
{
  return ereg_replace(
    string  : _FCT_ANON_ARGS[0],
    pattern : "^[ \t\r\n]*",
    replace : ""
  );
}

##
# Converts literal characters to their escaped representations.
#
# @anonparam blob A string.
#
# @remark This function does not handle Unicode properly. Adding that
#         functionality would require declaring the encoding of the
#         input.
#
# @return A string with all possible characters escaped.
##
function _escape()
{
  local_var blob, cc, i, len, s;

  blob = _FCT_ANON_ARGS[0];
  len = strlen(blob);

  s = "";
  for (i = 0; i < len; i++)
  {
    cc = blob[i];

    if (cc == '\\')
    {
      s += "\\";
    }
    else if (cc == raw_string(0x08))
    {
      s += "\b";
    }
    else if (cc == '\t')
    {
      s += "\t";
    }
    else if (cc == '\n')
    {
      s += "\n";
    }
    else if (cc == '\f')
    {
      s += "\f";
    }
    else if (cc == '\r')
    {
      s += "\r";
    }
    else if (cc == '"')
    {
      s += "\" + '"';
    }
    else if (cc == "/")
    {
      s += "\/";
    }
    else
    {
      s += cc;
    }
  }

  return s;
}

##
# Converts escaped representations to their literal characters.
#
# @anonparam blob A string.
#
# @remark This function does not handle Unicode properly. Adding that
#         functionality would require declaring the desired encoding
#         of the output.
#
# @return A string without characters escaped.
##
function _unescape()
{
  local_var blob, cc, i, len, s, uu;

  blob = _FCT_ANON_ARGS[0];
  len = strlen(blob);

  i = 0;
  s = "";
  while (i < len)
  {
    cc = substr(blob, i, i + 1);
    uu = substr(blob, i, i + 5);

    # Convert from escaped to literal version.
    if (cc == "\b")
    {
      s += raw_string(0x08);
      i += 2;
    }
    else if (cc == "\t")
    {
      s += '\t';
      i += 2;
    }
    else if (cc == "\n")
    {
      s += '\n';
      i += 2;
    }
    else if (cc == "\f")
    {
      s += '\f';
      i += 2;
    }
    else if (cc == "\r")
    {
      s += '\r';
      i += 2;
    }
    else if (cc == "\u")
    {
      s += uu;
      i += 6;
    }
    else if (cc == '\\"')
    {
      s += '"';
      i += 2;
    }
    else if (cc == "\/")
    {
      s += "/";
      i += 2;
    }
    else if (cc == "\\")
    {
      s += "\";
      i += 2;
    }
    else
    {
      s += cc[0];
      i++;
    }
  }

  return s;
}

##
# Removes from a string the token that's already been parsed.
#
# @anonparam blob A string in JSON format.
# @anonparam tok A token read by another parsing function.
#
# @return A string without the passed token in it.
##
function _tok_del()
{
  local_var blob, tok;

  blob = _FCT_ANON_ARGS[0];
  tok = _FCT_ANON_ARGS[1];

  # Remove the token from the string.
  blob = substr(blob, strlen(tok));

  # If the token was the last thing in the string, we want the result
  # of this operation to be an empty string, not NULL.
  if (!blob)
    return "";

  return blob;
}

######################################################################
# Private Input Functions
######################################################################

##
# Parses a constant from JSON.
#
# @anonparam blob A string in JSON format.
#
# @return A NASL constant.
##
function _json_read_const()
{
  local_var blob, matches, val;

  blob = _FCT_ANON_ARGS[0];

  # Try and match the constant.
  matches = eregmatch(string:blob, pattern:"^(false|null|true)");
  if (isnull(matches))
    return _error("Unrecognized constant", blob);

  # Change constant into NASL data.
  if (matches[0] == "false")
    val = 0;
  else if (matches[0] == "null")
    val = NULL;
  else if (matches[0] == "true")
    val = 1;
  else
    return _error("Failed to convert constant", blob);

  # Remove the portion of the blob that we've used.
  blob = _tok_del(blob, matches[0]);

  return _success(val, blob);
}

##
# Parses a number from JSON.
#
# @anonparam blob A string in JSON format.
#
# @return A NASL integer.
##
function _json_read_int()
{
  local_var blob, ds, matches;

  blob = _FCT_ANON_ARGS[0];

  # Try and match the integer.
  matches = eregmatch(string:blob, pattern:"-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][-+]?[0-9]+)?");
  if (isnull(matches))
    return _error("Failed to parse integer", blob);

  # Remove the portion of the blob that we've used.
  blob = _tok_del(blob, matches[0]);

  # Although we are passing numbers to int() which it does not
  # support, it will silently ignore things it doesn't recognize.
  return _success(int(matches[0]), blob);
}

##
# Parses a string from JSON.
#
# @anonparam blob A string in JSON format.
#
# @return A NASL string.
##
function _json_read_string()
{
  local_var blob, i, len, s;

  blob = _FCT_ANON_ARGS[0];

  if (blob[0] != '"')
    return _error('Expected opening \'"\'', blob);
  blob = _tok_del(blob, '"');

  s = "";
  len = strlen(blob);
  for (i = 0; i < len; i++)
  {
    if (blob[i] == '"')
    {
      break;
    }
    else if (
      (blob[i] == "\") &&
      (blob[i + 1] == "\" || blob[i + 1] == '"')
    )
    {
      s += blob[i];
      i++;
      s += blob[i];
    }
    else
    {
      s += blob[i];
    }
  }

  blob = _tok_del(blob, s);
  if (blob[0] != '"')
    return _error('Expected closing \'"\'', blob);
  blob = _tok_del(blob, '"');

  return _success(_unescape(s), blob);
}

##
# Parses an array from JSON.
#
# @anonparam blob A string in JSON format.
#
# @return A NASL list.
##
function _json_read_list()
{
  local_var blob, ds, i, res, val;

  blob = _FCT_ANON_ARGS[0];

  # Consume the opening bracket.
  if (blob[0] != "[")
    return _error("Expected '['", blob);
  blob = _tok_del(blob, "[");

  # Consume whitespace.
  blob = _trim(blob);

  # Parse the values in the array.
  ds = make_list();
  for (i = 0; TRUE; i++)
  {
    # A closing bracket means the array is empty.
    if (blob[0] == "]")
      break;

    # Parse the value.
    res = json_read(blob);

    # Check for parse error.
    blob = res[1];
    if (isnull(blob))
      return res;

    val = res[0];

    # Add the value to the list. Note that we must insert it with an
    # explicit index, as opposed to using make_array(ds, val). This
    # prevent val from being collapsed if it's a nested list or array.
    ds[i] = val;

    # Consume the separator.
    blob = _trim(blob);
    if (blob[0] != ",")
      break;
    blob = _tok_del(blob, ",");
    blob = _trim(blob);
  }

  # Consume the closing bracket.
  if (blob[0] != "]")
    return _error("Expected ']'", blob);
  blob = _tok_del(blob, "]");

  return _success(ds, blob);
}

##
# Parses an object literal from JSON.
#
# @anonparam blob A string in JSON format.
#
# @return A NASL array.
##
function _json_read_array()
{
  local_var blob, ds, key, res, val;

  blob = _FCT_ANON_ARGS[0];

  # Consume the opening brace.
  if (blob[0] != "{")
    return _error("Expected '{'", blob);
  blob = _tok_del(blob, "{");

  # Consume whitespace.
  blob = _trim(blob);

  # Parse the key value pairs in the object literal.
  ds = make_array();
  while (TRUE)
  {
    # A closing brace means the object literal is empty.
    if (blob[0] == "}")
      break;

    # Parse the key.
    res = _json_read_string(blob);

    # Check for parse error.
    blob = res[1];
    if (isnull(blob))
      return res;

    key = res[0];

    # Consume the key value separator.
    blob = _trim(blob);
    if (blob[0] != ":")
      return _error("Expected ':'", blob);
    blob = _tok_del(blob, "{");
    blob = _trim(blob);

    # Parse the value.
    res = json_read(blob);

    # Check for parse error.
    blob = res[1];
    if (isnull(blob))
      return res;

    val = res[0];

    # Add the key value pair to the array.
    ds[key] = val;

    # Consume the element separator.
    blob = _trim(blob);
    if (blob[0] != ",")
      break;
    blob = _tok_del(blob, ",");
    blob = _trim(blob);
  }

  # Consume the closing brace.
  if (blob[0] != "}")
    return _error("Expected '}'", blob);
  blob = _tok_del(blob, "}");

  return _success(ds, blob);
}

######################################################################
# Private Output Functions
######################################################################

##
# Produces a JSON representation of an integer.
#
# @anonparam ds An integer.
#
# @return String in JSON format representing the given integer as a
#         JSON number.
##
function _json_write_int()
{
  local_var ds;

  ds = _FCT_ANON_ARGS[0];

  return string(ds);
}

##
# Produces a JSON representation of a double-quoted a string.
#
# @anonparam ds A double-quoted string.
#
# @return String in JSON format representing the given double-quoted
#         string as a JSON string.
##
function _json_write_string()
{
  local_var ds;

  ds = _FCT_ANON_ARGS[0];

  return '"' + _escape(ds) + '"';
}

##
# Produces a JSON representation of a single-quoted string.
#
# @anonparam ds A single-quoted string.
#
# @return String in JSON format representing the given single-quoted
#         string as a JSON string.
##
function _json_write_data()
{
  local_var ds;

  ds = _FCT_ANON_ARGS[0];

  return _json_write_string(ds);
}

##
# Produces a JSON representation of an undefined value.
#
# @anonparam ds An undefined value (i.e. NULL).
#
# @return String in JSON format representing the given undefined value
#         as a JSON null.
##
function _json_write_undef()
{
  local_var ds;

  ds = _FCT_ANON_ARGS[0];

  return "null";
}

##
# Produces a JSON representation of a list.
#
# @anonparam ds A list.
#
# @return String in JSON format representing the given list as a JSON
#         array.
##
function _json_write_list()
{
  local_var ds, vals, i, max;

  ds = _FCT_ANON_ARGS[0];

  # Convert each value in the list to JSON.
  vals = make_list();

  max = path_max(ds);
  for (i = 0; i < max ; i++)
    vals[i] = json_write(path_child(ds, i));

  # Bundle all the values together in a JSON array.
  return "[" + join(vals, sep:",") + "]";
}

##
# Produces a JSON representation of an array.
#
# @anonparam ds An array.
#
# @remark The array's pairs will be written out in sorted order based
#         on the keys. This permits better comparison if a structure
#         is repeatedly read in and written back out.
#
# @return String in JSON format representing the given as a JSON object
#         literal.
##
function _json_write_array()
{
  local_var ds, key, pair, pairs, val;

  ds = _FCT_ANON_ARGS[0];

  pairs = make_list();

  foreach key (sort(path_keys(ds)))
  {
    val = json_write(path_child(ds, key));

    # Keys must be strings.
    if (typeof(key) == "int")
      key = string(key);
    key = _json_write_string(key);

    pair = key + ":" + val;
    pairs = make_list(pairs, pair);
  }

  # Bundle all the values together in a JSON object literal.
  return "{" + join(pairs, sep:",") + "}";
}

##
# Reformats the output from [builtin.inc#xmlparse].
#
# @anonparam xml An array.
#
# @return An array with the new format.
##
function _xml_format()
{
  local_var attr, attrs, child, cindex, collapsible, i, merged, name;
  local_var new, old, tag, tmp, v, xml;

  xml = _FCT_ANON_ARGS[0];

  # Create a new array that will represent the tag.
  tag = make_array();

  # Reformat the tag's contents.
  v = path_get(xml, "value"); # xml["value"]

  if (!isnull(v))
  {
    v = strip(v);
    if (strlen(v) > 0)
      tag["#text"] = v;
  }

  # Reformat the tag's attributes.
  attrs = path_get(xml, "attributes"); # xml["attributes"]

  if (!isnull(attrs))
  {
    foreach attr (keys(attrs))
    {
      tag["@" + attr] = attrs[attr]; #xml["attributes"][attr];
    }
  }

  # Reformat the tag's children.
  merged = make_array();
  cindex = path_max(xml, "children");

  for (i = 0; i < cindex; i++)
  {
    child = path_child(xml, "children", i);

    if (path_max(child, "children") == 0 && path_isnull(child, "value"))
      continue;

    name = tolower(path_get(child, "name"));
    new = _xml_format(child);

    # Pull children into an array if duplicate tags exist.
    if (!isnull(tag[name]))
    {
      if (merged[name] == FALSE)
      {
        tmp = tag[name];
	merged[name] = TRUE;
	tag[name] = make_list();
	tag[name][0] = tmp;
      }

      tag[name][max_index(tag[name])] = new;
    }
    else
    {
      merged[name] = FALSE;
      tag[name] = new;
    }
  }

  # Collapse merged children that have the same name and only text
  # with no attributes or children of their own.
  foreach name (keys(merged))
  {
    # Skip unmerged children.
    if (!merged[name])
      continue;

    # Evaluate if children can be merged.
    collapsible = TRUE;
    foreach child (tag[name])
    {
      if (max_index(keys(child)) != 1 || isnull(child["#text"]))
      {
        collapsible = FALSE;
        break;
      }
    }

    if (!collapsible)
      continue;

    # Collapse children.
    tmp = tag[name];
    tag[name] = make_list();

    foreach child (tmp)
    {
      tag[name] = make_list(tag[name], child["#text"]);
    }
  }

  # Collapse unmerged children that have only text with no attributes
  # or children of their own.
  foreach name (keys(merged))
  {
    # Skip merged children.
    if (merged[name])
      continue;

    child = tag[name];

    # Skip uncollapsible children.
    if (max_index(keys(child)) != 1 || isnull(child["#text"]))
      continue;

    tag[name] = child["#text"];
  }

  return tag;
}

######################################################################
# Public Functions
######################################################################

##
# Produces a NASL data structure from JSON.
#
# @anonparam blob A string in JSON format.
#
# @return A NASL data structure represented by the given JSON.
##
function json_read()
{
  local_var blob;

  # Ensure that we were actually given a string to parse.
  blob = _FCT_ANON_ARGS[0];
  if (isnull(blob))
    return _error("A NULL value cannot be parsed");

  # Remove leading whitespace.
  blob = _trim(blob);

  # An empty string is not valid.
  if (blob == "")
    return _error("Empty blob cannot be parsed");

  if (blob[0] =~ "[0-9]" || blob[0] == "-" && blob[1] =~ "[0-9]")
    return _json_read_int(blob);

  if (blob[0] == '"')
    return _json_read_string(blob);

  if (blob[0] =~ "[a-z]")
    return _json_read_const(blob);

  if (blob[0] == "[")
    return _json_read_list(blob);

  if (blob[0] == "{")
    return _json_read_array(blob);

  # If none of the above parsing functions match, we have an error.
  return _error("Parser is in an unknown state", blob);
}

##
# Produces a JSON representation of data.
#
# @anonparam ds Any NASL literal, variable, or data structure.
#
# @return String in JSON format representing the given data.
##
function json_write()
{
  local_var ds, type;

  ds = _FCT_ANON_ARGS[0];
  type = path_typeof(ds);

  # This type represents both integers and the constants TRUE and
  # FALSE.
  if (type == "int")
    return _json_write_int(path_get(ds));

  # This type represents double-quoted strings.
  if (type == "string")
    return _json_write_string(path_get(ds));

  # This type represents single-quoted strings.
  if (type == "data")
    return _json_write_data(path_get(ds));

  # This type represents both the constant NULL and undefined
  # variables.
  if (type == "undef")
    return _json_write_undef(ds);

  # This type represents both arrays and lists, since the latter is
  # implemented as the former. JSON, however, distinguishes between
  # the two, so we need to be able to write out both or risk not being
  # able to interact with certain services.
  if (type == "array")
  {
    if (_is_list(ds))
      return _json_write_list(ds);
    else
      return _json_write_array(ds);
  }

  # Unsupported data type, we have to fail or create a representation
  # that can't faithfully recreate the input.
  return NULL;
}

##
# Produces a JSON representation of XML.
#
# @anonparam xml Either XML as a string, or the array produced by
#                xmlparse().
#
# @return String in JSON format representing the given data.
##
function json_xml()
{
  local_var cxml, json, jtag, name, tag, type, xml;

  xml = _FCT_ANON_ARGS[0];
  type = typeof(xml);

  # Parse XML if not already done.
  if (type != "array")
  {
    # Can only parse text types.
    if (type != "data" && type != "string")
      return NULL;

    xml = xmlparse(xml);
    if (isnull(xml))
      return NULL;
  }

  # Wrap raw XML in path library for efficient access, deleting the
  # other copy of it.
  name = tolower(xml["name"]);
  cxml = path_store(xml);
  xml = NULL;

  # Reformat the XML data structure to our liking.
  tag = make_array();
  tag[name] = _xml_format(cxml);

  # Remove XML from path library.
  path_free(cxml);

  # Store reformatted XML in path, deleting the other copy of it.
  jtag = path_store(tag);
  tag = NULL;

  # Convert XML to JSON and remove the reformatted XML from the path
  # library.
  json = json_write(jtag);
  path_free(jtag);

  return json;
}
