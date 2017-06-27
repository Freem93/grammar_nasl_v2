#TRUSTED 048989147d5649d9b203c3f58f3068be1850ac0477ce21b22bd61a47f56dfc18dc9b51254004fdaff8d71ef96eaa9187786248a2fce9c53cda0e5e4233ac5b01c798a33f785e49c6a125215e183c435a2c2bcf51dc869216abce698b3da709ee544f2fb6d644097506e6cd3c1821b8f80de05fd624cafc67d4fdd002e38fb487e073785a71e1756c82423896d7b3e8d731e9ef1a0ce2db37da82dc5206aaed2f97b3b07afc690c12aeb301264f926115e72bb0b3ced7a59227a42ed57d5707598bceef7ff530ee2149c534bed4d54e9af32ff20b74f42d74282609c5670cdbe950466c743cc1ccbcfcab2a0ee0028ecf835063551902fdeac3c10a3dc9d8709862962589ff895ab56205c5f9abd5cf460ba8ed0754104e3afd91e9484f2574a13d33bc7109d83f96da738b675e14258cb1192f4754060b8ba3b1cd5b77de53010cd405ac7b84e27db33860e64a73896fa54153ccc2402e7711cabd776c74e889adc66614104c6cbc718449d835207435c624e55fa883866439aed1da60ebbfdef918b2137817c1e129ba1da4ed9e950e8f5b2b4340a7170c8150ea2743f96ddf3462b7ccdc0e36109f257fcc07bbb27ac528967ad96ec8a69e2e347827c787ea5bea20fa8a03159eb06676ac6071fd3b481c6127126cd61672876806b9e238e6716de3ef7599d542cd246d12da9868aefa3bd44cb5636517f2630b5cab4e0f62

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
#
##
# The purpose of this file is to make it easier to parse and analyze large
# XML structures. Note that these functions operate on tables, not directly
# on XML - the tables are the ones created by xmlparse(). 
##

###
# A mapping between characters used in syntax and their entity names.
# e.g. & corresponds to "amp".
#
# The purpose of this list is to allow translation such as converting <
# to &lt; though the "&" and ";" are not included in the table entries.
###
global_var XML_SYNTAX_CHAR_TABLE;
XML_SYNTAX_CHAR_TABLE = make_array(
  '"', "quot",
  '&', "amp",
  "'", "apos",
  '<', "lt",
  '>', "gt"
);

##
# Retrieve the first child in the node with the given name. For example,
# in the following XML structure:
#
# <authors>
#   <author>Ron</author>
#   <author>John</author>
# </author>
#
# Calling this for the name 'author' would return a table representing the
# first author ("Ron"). 
#
# @param table An XML table, returned by xmlparse() or any of the various
#              xml_get_* functions. 
# @param name  The name to retrieve.
#
# @return An XML tables representing the node, or NULL if none were found.
##
function xml_get_child(table, name)
{
  local_var child;

  if(isnull(name))
    exit(1, "Invalid 'name' value passed to xml_get_child.");

  foreach child(table['children'])
  {
    if(child['name'] == name)
      return child;
  }

  return NULL;
}

##
# Retrieve all children in the node with the given name. For example,
# in the following XML structure:
#
# <authors>
#   <author>Ron</author>
#   <author>John</author>
# </author>
#
# Calling this for the name 'author' will return an array containing two
# elements - the node for 'Ron' and the node for 'John'. 
#
# @param table An XML table, returned by xmlparse() or any of the various
#              xml_get_* functions. 
# @param name  The name to retrieve.
#
# @return An array of XML tables representing the nodes, or NULL if none were
#         found. 
##
function xml_get_children(table, name)
{
  local_var child, result;

  if(isnull(name))
    exit(1, "Invalid 'name' value passed to xml_get_child.");

  result = make_list();
  foreach child(table['children'])
  {
    if(child['name'] == name)
      result[max_index(result)] = child;
  }

  return result;
}

## 
# Get a list of names of all sub-nodes. For example, in the following XML
# structure:
#
# <author>
#   <name>Ron</name>
#   <country>Canada</country>
# </author>
#
# Calling this would return a list containing 'name' and 'country'. 
#
# @param table An XML table, returned by xmlparse() or any of the various
#              xml_get_* functions. 
# @return An array of names, or an empty array if this node was empty.
##
function xml_get_children_names(table)
{
  local_var child, result;

  result = make_list();
  foreach child(table['children'])
    result = make_list(result, child['name']);

  return result;
}

## 
# Get a list of name/value pairs of all sub-nodes. For example, in the
# following XML structure:
#
# <author>
#   <name>Ron</name>
#   <country>Canada</country>
# </author>
#
# Calling this would return a list containing 'name'=>'Ron' and
# 'country'=>'Canada'.
#
# @param table An XML table, returned by xmlparse() or any of the various
#              xml_get_* functions. 
# @return An array of names/values, or an empty array if this node was empty.
##
function xml_get_names_values(table)
{
  local_var child, result;

  result = make_array();
  foreach child(table['children'])
    result[child['name']] = child['value'];

  return result;
}

##
# Attempt to turn the XML table back into an XML string. This isn't 100%
# effective - for example, it doesn't properly encode symbols - so at the
# moment it's best to use this for debugging purposes only.
#
# @param table   An XML table, returned by xmlparse() or any of the various
#                xml_get_* functions. 
# @param _indent An internal variable used for recursion.
# @return A string representing the XML data. 
##
function _xml_table_to_string(table, _indent)
{
  local_var _indent_str, result, attribute, child;

  if(isnull(_indent))
    _indent = 0;
  _indent_str = crap(data:' ', length:_indent * 2);

  # Do the opening tag
  result = _indent_str + "<" + table['name'];
  foreach attribute(keys(table['attributes']))
    result = result + (' ' + attribute + '="' + table['attributes'][attribute] + '"');  

  # If the string is all space/newline, it's basically blank
  if(preg(string:table['value'], pattern:'^[ \n]*$', multiline:TRUE))
    table['value'] = NULL;

  # Handle a 'value' field
  if(!isnull(table['value']) && table['value'] != '')
  {
    result = result + '>' + table['value'] + "</" + table['name'] + '>\n';
  }
  # Handle the case where there are no children
  else if(max_index(table['children']) == 0)
  {
    result = result + '\\>\n';
  }
  # Handle the case where there are children
  else
  {
    result = result + '>\n';

    foreach child(table['children'])
    {
      result = result + xml_table_to_string(table:child, _indent:_indent + 1);
    }
    result = result + _indent_str + "</" + xml['name'] + '>\n';
  }

  return result;
}

##
# Replace syntactical characters with XML entities such that it is safe
# to use the given string in attribute values and content.
#
# @anonparam str The string to replace the characters in.
#
# @remark Non-idempotent; this function will re-escape already escaped strings.
#
# @return a string suitable for an attribute value or textual content.
##
function xml_escape()
{
  local_var char, replacement, str;

  str = _FCT_ANON_ARGS[0];

  # Substitute "&" first so we don't escape any we add.
  foreach char (list_uniq(make_list("&", keys(XML_SYNTAX_CHAR_TABLE))))
  {
    replacement = "&" + XML_SYNTAX_CHAR_TABLE[char] + ";";
    str = str_replace(string:str, find:char, replace:replacement);
  }

  return str;
}
