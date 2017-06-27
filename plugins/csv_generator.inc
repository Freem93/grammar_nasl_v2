##
# Escapes CSV field based on RFC4180
# @param [data:string] Field data to escape
#
# @return escaped field
##
function escape_csv_field(data)
{
  local_var ret, quote;

  quote = FALSE;
  ret = data;
  if ('"' >< ret)
  {
    ret = str_replace(string:data, find:'"', replace:'""');
    quote = TRUE;
  }

  if (',' >< ret || '\r' >< ret || '\n' >< ret)
  {
    quote = TRUE;
  }

  if (quote)
  {
    ret = '"' + ret + '"';
  }

  return ret;
}

##
# Generate CSV from data
#
# @param header List of arrays. 
#               Each array has the required key "key" which is the key for
#               the record in data being passed in.
#               optional keys:
#               format - function reference to run to format the data before inserting into CSV.
#                        takes named argument data and returns data in desired format.
#               name   - if available will be used in header record instead of defaulting to key.
# @param data List or array of arrays. Contains data for CSV described by header.
#
# @return CSV as string
##
function generate_csv(header, data)
{
  local_var csv, value, record;

  csv = '';

  foreach value(header)
  {
    if (!isnull(value["name"]))
    {
      csv += escape_csv_field(data:value["name"]);
    }
    else
    {
      csv += escape_csv_field(data:value["key"]);
    }
    csv += ',';
  }
  csv = substr(csv, 0, strlen(csv)-2);
  csv += '\n';

  foreach record(data)
  {
    foreach value(header)
    {
      if (!isnull(value["format"]) && typeof(value["format"]) == "function")
      {
        csv += escape_csv_field(data:value["format"](data:record[value["key"]]));
      }
      else
      {
        csv += escape_csv_field(data:record[value["key"]]);
      }
      csv += ',';
    }
    csv = substr(csv, 0, strlen(csv)-2);
    csv += '\n';
  }

  return csv;
}

##
# Generate header for generate_csv() from data.
#
# @param data List or array of arrays.
# @param header Optional header for static header items.
#
# @return header
##
function header_from_data(data, header)
{
  local_var new_header, header_keys, existing_keys, value, key;

  header_keys = make_array();
  existing_keys = make_array();

  if (isnull(header))
  {
    new_header = make_list();
  }
  else
  {
    new_header = header;
    foreach value(header)
    {
      existing_keys[value["key"]] = TRUE;
    }
  }

  foreach value(data)
  {
    foreach key(keys(value))
    {
      if (isnull(existing_keys[key]))
      {
        header_keys[key] = TRUE;
      }
    }
  }

  foreach key(keys(header_keys))
  {
    new_header[max_index(new_header)] = make_array("key", key);
  }

  return new_header;
}

##
# Generate header for generate_csv() from a list of keys.
#
# @param [list:list] List of keys.
#
# @return header
##
function header_from_list(list)
{
  local_var header, value;
  header = make_list();

  foreach value(list)
  {
    header[max_index(header)] = make_array("key", value);
  }

  return header;
}
