#TRUSTED a2775ad00d893c3bda8f02a7f58757e1819c1f77b5e29084fcc8b4f2622cc314b19e42840ee51778f5a6adc7d3b67a8e15ab1da1b79352d5251c130c8da9b248e92ef2d3b988e291ab3b8df88f71e576322f974f045693f3e41f11bd18e3e0613f597f7639577720599471a0ed1efc6cbc050a7d8e2f9d9d37f68d0b9bf919716549f46f1a9ef3ac2a8992b2790d2625292794328dfc45c9a6714334ef9cc54bc7ab68044555901c86462e9fda68a04a62a1a17dbf08945a836f60fbe6e6ad13f7cf5641c4ede00819f8977aa5b590bd0754a181aae76812b75227c09ef35e36a374a97b912d7191e39d3f43e6163f61c2539c4481879d1bc47d233cdbf8c5015709de2c021e59537f4bbff6fbea8f85315d46100f3e262b8c1abf0a395a7c738ff37e1a160b637d7496e35305dcbfc4f8a679484240211b16cc3b784a7a888bd2103f2b33b65bced906a8ba7d3edd85029bd9e04056b44da351e7359ac2af6064be94744897c689b5ea6120b85e2349597055af2501961d473c64525c96ab6d170596c21c48d752da61e6bc2fd1d3bf7efb662fc46c54013d8df8d2154d37d1033bcd0854adcbadd280a4ecc3e4d83978d4709f005da364d802d0fcc91b1359a7b9c0c8e09068a2297b22c810adcd86337fb8dbcc9949ae091cedcddacdeffc7f1246def505cd7541faeed827d64426485b5fe7fb6a419976b2510ff04364e7
#
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
#
# @NOGPL@
#
# microsoft_azure.inc
# Revision: 1.1
#
include("json.inc");

global_var AZURE_API_HOST, AZURE_API, AZURE_HOST_TAG_BASE, AZURE_KB_BASE, success, failure;

##
# Azure API Host
##
AZURE_API_HOST = "169.254.169.254";

##
# Azure API configurations
#   Headers : required HTTP headers
#   Content : output format to be parsed
#   Items   : API items to gather
##
AZURE_API["/metadata/latest/InstanceInfo"] = make_array(
  "Content", "JSON",
  "Items", make_array(
    "ID", "Instance Name (ID)",
    "UD", "Update Domain (UD)",
    "FD", "Fault Domain (FD)")
);

AZURE_API["/machine?comp=goalstate"] = make_array(
  "Headers", make_array(
    "x-ms-guest-agent-name", "WaAgent-2.5.0.0 (2.7.0.0)",
    "x-ms-version", "2015-04-05"),

  "Content", "XML",
  "Items", make_array(
    "ContainerId", "ContainerId",
    "InstanceId",  "InstanceId",
    "State",       "State")
);

##
# XML Host Tag base
##
AZURE_HOST_TAG_BASE = "azure-instance";

##
# KB Base
##
AZURE_KB_BASE = "Host/Azure";

##
# Parses output
#
# @param string output to be parsed
# @param string content of the output (XML, JSON)
# @param array  items to parse out of the output
# 
# @return array like {"api_item_1" : "api_value_1", ... "api_item_N" : "api_value_N"} if API items were found
#         NULL  if an error occurred or no API items were found
##
function azure_parse_output(output, content, items)
{
  local_var item, items_found, matches, pairs, json_object, key;

  if (empty_or_null(output) || empty_or_null(content) || empty_or_null(items))
    return NULL;

  if (typeof(output) !~ '(data|string)' || typeof(content) !~ '(data|string)' || typeof(items) != 'array')
    return NULL;

  items_found = make_array();

  if (content == "XML")
  {
    # Remove newlines and return carriages we don't need them and they can cause issues
    output = str_replace(string:output, find:'\r', replace:'');
    output = str_replace(string:output, find:'\n', replace:'');

    foreach item (keys(items))
    {
      matches = pregmatch(string:output, pattern:"<"+item+">([^<]+)</"+item+">", icase:TRUE);
      if (!isnull(matches))
        items_found[item] = matches[1];
    }
  }
  else if (content == "JSON")
  {
    # Compile array of all key/value pairs (the keys are unique AFAIK)
    pairs = make_array();
    foreach json_object (json_read(output))
    {
      if (empty_or_null(json_object) || typeof(json_object) != 'array') continue;

      foreach key (keys(json_object))
        pairs[key] = json_object[key];
    }
    # Parse out the specified items and store them
    foreach item (keys(items))
    {
      if (!empty_or_null(pairs[item]))
        items_found[items[item]] = pairs[item];
    } 
  }
  # content type not supported
  else
    return NULL;

  if (!empty_or_null(items_found))
    return items_found;

  # No API items found
  return NULL;
}
