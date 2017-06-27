#TRUSTED 27a14e2877dab00a44643081d61db562694cba609075e2f8de273775bd0e09e017a22153d41661ae0dd83deda57f6f6b89c8974ae6bb23e77cd679173aee3d76a1f5c3a70da3a20336cb44b3dc82e12be9a89fb2771e6e92a79d6350ae8e66964473819a047e9a2b4fe55943cca55978553fc233e7cbc8ec6c22b92717a36ec980ac89aa0fe2d93c7234fb67b684156919d013766320384a3ef0c3757d55e0f43d0098528bf312ea6bf5efbd161f5a6a49142c9132ba078f82b3904aa182426421f8b47a71c7552b7caa98dee57fa33d41349813ba6b63b857d37a9e2a3945f8fdbe49db6d93ed19226c65377862a5e669815163314db4277a9aea9094023ed086682bf5718caad9b5970ff0a45b0a9abcb3371699331b774f0fc9c2e7f1cfe94cb473323804cb881cc5b16734dcb470d82c5ea9d1ee8c4264932e96f4b6adf3ae379aa369aea7566d101b5524de713f594bb16183a9c46a566d0be6c46fd62e987223d8ac44f34710e6bc1124b76c3ed683132e545a0129d8672c7b357d344547222d488477e00d227936f5bc67bd7a08a70c0d12f6544bfde70ab0034d43065793a83dccb4d049ca598f563e58d4cd07243137c1820535144a6275cae4487561d4ba960e55a93b4f8a9acb19f3416fc2f63d38a32cef321aa8af0f814ae1f610a20b0469d9fbdd3b80b847aad134e09e6f9a7424b4fe9b8363ca13367f4331
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# mysql_func.inc
# Revision 1.20
#
# This library is used to communicate using the MySQL Client/Server protocol.
# Data cached in the KB is used whenever possible, connections are only made
# when information desired by the caller is not available in the KB.
#
# For information on the MySQL Client/Server protocol, see :
# http://forge.mysql.com/wiki/MySQL_Internals_ClientServer_Protocol
#
###

include("byte_func.inc");

# Globals are from include/mysql_com.h

##
# new more secure passwords
##
global_var CLIENT_LONG_PASSWORD;
CLIENT_LONG_PASSWORD     = 1;

##
# Found instead of affected rows
##
global_var CLIENT_FOUND_ROWS;
CLIENT_FOUND_ROWS        = 2;

##
# Get all column flags
##
global_var CLIENT_LONG_FLAG;
CLIENT_LONG_FLAG         = 4;

##
# One can specify db on connect
##
global_var CLIENT_CONNECT_WITH_DB;
CLIENT_CONNECT_WITH_DB   = 8;

##
# Don't allow database.table.column
##
global_var CLIENT_NO_SCHEMA;
CLIENT_NO_SCHEMA         = 16;

##
# Can use compression protocol
##
global_var CLIENT_COMPRESS;
CLIENT_COMPRESS          = 32;

##
# Odbc client
##
global_var CLIENT_ODBC;
CLIENT_ODBC              = 64;

##
# Can use LOAD DATA LOCAL
##
global_var CLIENT_LOCAL_FILES;
CLIENT_LOCAL_FILES       = 128;

##
# Ignore spaces before '('
##
global_var CLIENT_IGNORE_SPACE;
CLIENT_IGNORE_SPACE      = 256;

##
# New 4.1 protocol
##
global_var CLIENT_PROTOCOL_41;
CLIENT_PROTOCOL_41       = 512;

##
# This is an interactive client
##
global_var CLIENT_INTERACTIVE;
CLIENT_INTERACTIVE       = 1024;

##
# Switch to SSL after handshake
##
global_var CLIENT_SSL;
CLIENT_SSL               = 2048;

##
# IGNORE sigpipes
##
global_var CLIENT_IGNORE_SIGPIPE;
CLIENT_IGNORE_SIGPIPE    = 4096;

##
# Client knows about transactions
##
global_var CLIENT_TRANSACTIONS;
CLIENT_TRANSACTIONS      = 8192;

##
# Old flag for 4.1 protocol
##
global_var CLIENT_RESERVED;
CLIENT_RESERVED          = 16384;

##
# New 4.1 authentication
##
global_var CLIENT_SECURE_CONNECTION;
CLIENT_SECURE_CONNECTION = 32768;

##
# Enable/disable multi-stmt support
##
global_var CLIENT_MULTI_STATEMENTS;
CLIENT_MULTI_STATEMENTS  = 65536;

##
# Enable/disable multi-results
##
global_var CLIENT_MULTI_RESULTS;
CLIENT_MULTI_RESULTS     = 131072;

##
# Multi-results in PS-protocol
##

global_var CLIENT_PS_MULTI_RESULTS;
CLIENT_PS_MULTI_RESULTS  = 1 << 18;

##
# Supports authentication plugins.
##
global_var CLIENT_PLUGIN_AUTH;
CLIENT_PLUGIN_AUTH = 0x00080000;

##
# Length of auth response data is a length-encoded integer.
##
global_var CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA;
CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 0x00200000;

##
#
##
global_var CLIENT_SSL_VERIFY_SERVER_CERT;
CLIENT_SSL_VERIFY_SERVER_CERT = 1 << 30;

##
#
##
global_var CLIENT_REMEMBER_OPTIONS;
CLIENT_REMEMBER_OPTIONS = 1 << 31;

##
# Transaction has started
##
global_var SERVER_STATUS_IN_TRANS;
SERVER_STATUS_IN_TRANS             = 1;

##
# Server in auto_commit mode
##
global_var SERVER_STATUS_AUTOCOMMIT;
SERVER_STATUS_AUTOCOMMIT           = 2;

##
# Multi query - next query exists
##
global_var SERVER_MORE_RESULTS_EXISTS;
SERVER_MORE_RESULTS_EXISTS         = 8;

##
#
##
global_var SERVER_QUERY_NO_GOOD_INDEX_USED;
SERVER_QUERY_NO_GOOD_INDEX_USED    = 16;

##
#
##
global_var SERVER_QUERY_NO_INDEX_USED;
SERVER_QUERY_NO_INDEX_USED         = 32;

##
#The server fulfilled the clients request and opened a read-only non-scrollable cursor for a query.
##
global_var SERVER_STATUS_CURSOR_EXISTS;
SERVER_STATUS_CURSOR_EXISTS        = 64;

##
#This flag is sent when a read-only cursor is exhausted, in reply to COM_STMT_FETCH command.
##
global_var SERVER_STATUS_LAST_ROW_SENT;
SERVER_STATUS_LAST_ROW_SENT        = 128;

##
# database was dropped
##
global_var SERVER_STATUS_DB_DROPPED;
SERVER_STATUS_DB_DROPPED           = 256;

##
#
##
global_var SERVER_STATUS_NO_BACKSLASH_ESCAPES;
SERVER_STATUS_NO_BACKSLASH_ESCAPES = 512;

##
# New prepared statement returns a different number of set columns
##
global_var SERVER_STATUS_METADATA_CHANGED;
SERVER_STATUS_METADATA_CHANGED     = 1024;

##
#
##
global_var SERVER_QUERY_WAS_SLOW;
SERVER_QUERY_WAS_SLOW              = 2048;

##
# To mark ResultSet containing output parameter values.
##
global_var SERVER_PS_OUT_PARAMS;
SERVER_PS_OUT_PARAMS               = 4096;

###
# Command for text-based queries that are executed immediately.
#
# Corresponds to COM_QUERY in mysql_com.h's enum_server_command.
#
# For more information, see https://dev.mysql.com/doc/internals/en/com-query.html
##
global_var SERVER_COMMAND_COM_QUERY;
SERVER_COMMAND_COM_QUERY = 3;

##
# hash used to cache info about the MySQL server
##
global_var _mysql;


set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

##
# Initialize this library and connect to the MySQL server.
#
# @remark This must be called before interacting with the MySQL server with
#   this library.
#
# @param host Optional parameter to indicate which host to connect to.
# @param port The port the MySQL server is listening on.
# @param nocache Do not pull server-specific info from the KB and instead open fresh.
# @param exit_on_fail Whether to exit in the case of failure.
#
# @return Returns 1 on success, -1 on failure.
##
function mysql_init(host, port, nocache, exit_on_fail)
{
  local_var kb_base;

  if (isnull(port))
  {
    display("mysql_init: 'port' argument is missing.\n");
    return -1;
  }

  if (isnull(nocache))
    nocache = FALSE;

  if (isnull(exit_on_fail))
    exit_on_fail = FALSE;

  _mysql["host"] = host;
  _mysql["port"] = port;
  _mysql["soc"] = NULL;

  # Pull server-specific info from the KB when possible.
  kb_base = mysql_kb_base();
  if (!nocache && get_kb_item(kb_base+'port'))
  {
    _mysql["proto"] = get_kb_item(kb_base+'proto');
    _mysql["ver"] = get_kb_item(kb_base+'ver');
    _mysql["caps"] = get_kb_item(kb_base+'caps');
    _mysql["lang"] = get_kb_item(kb_base+'lang');
    _mysql["status"] = get_kb_item(kb_base+'status');
    return 1;
  }

  return mysql_open(exit_on_fail:exit_on_fail);
}

##
# Generate a base string for use saving/getting MySQL KB items.
# This string is in the form mysql/<port>/ or mysql/external/<host>/<port>/.
#
# If no arguments are provided, retrieve information from _mysql["host"] and
# _mysql["port"].
#
# @param port The port the MySQL server is listening on.
# @param host Optional address to include to differentiate from target.
#
# @return Base string for MySQL KB items.
##
function mysql_kb_base(port, host)
{
  local_var base;

  if (isnull(host) && isnull(port))
  {
    port = _mysql["port"];
    host = _mysql["host"];
  }

  base = "mysql/";
  if (!isnull(host)) base += "external/" + host + "/";
  base += port + "/";

  return base;
}

function mysql_open(exit_on_fail)
{
  local_var hip, host, kb_base, l, port, soc, error, audit_msg;

  if (isnull(_mysql))
  {
    display("mysql_open: need to call mysql_init first.\n");
    return -1;
  }

  port = _mysql["port"];
  host = _mysql["host"];
  # We use open_sock2 only if host is defined in order to preserve old code,
  # the consequences of using open_sock2 in both cases is unknown.
  if (isnull(host)) soc = open_sock_tcp(port);
  else soc = open_sock2(host:host, port:port);

  if (!soc)
  {
    if (exit_on_fail) exit(1, "Can't open socket on port "+port+".");
    else return -1;
  }
  _mysql["soc"] = soc;

  hip = mysql_recv_packet();
  if (isnull(hip))
  {
    mysql_close();
    if (exit_on_fail) exit(1, "The service on port "+port+" failed to send a Handshake Initialization packet.");
    else return -1;
  }

  if (mysql_is_error_packet(packet:hip))
  {
    _mysql["err"] = hip;

    if (exit_on_fail)
    {
      error = mysql_get_last_error();
      audit_msg =
        'Error connecting to server on port ' + port + ' :\n' +
        'Error code    : ' +  error['num'] + '\n' +
        'Error message : ' +  error['msg'];
      exit(0, audit_msg);
    }
    else
      return 0;
  }
  else _mysql["err"] = NULL;

  _mysql["proto"]     = getbyte(blob:hip["data"], pos:0);
  _mysql["ver"]       = mysql_get_null_string(blob:hip["data"], pos:1);
  l = strlen(_mysql["ver"]);
  _mysql["thread_id"] = getdword(blob:hip["data"], pos:2+l);
  _mysql["salt"]      = substr(hip["data"], 6+l, 13+l);
  _mysql["caps"]      = getword(blob:hip["data"], pos:15+l);
  _mysql["lang"]      = getbyte(blob:hip["data"], pos:17+l);
  _mysql["status"]    = getword(blob:hip["data"], pos:18+l);
  # nb: I didn't find this addition to the salt documented on mysql.com,
  #     but Net::MySQL uses it.
  if (mysql_is_proto41_supported() && strlen(hip["data"]) > 44+l)
    _mysql["salt2"] = substr(hip["data"], 33+l, 44+l);

  # Cache server-specific info in the KB.
  kb_base = mysql_kb_base();
  replace_kb_item(name:kb_base+'port', value:_mysql["port"]);
  replace_kb_item(name:kb_base+'proto', value:_mysql["proto"]);
  replace_kb_item(name:kb_base+'ver', value:_mysql["ver"]);
  replace_kb_item(name:kb_base+'caps', value:_mysql["caps"]);
  replace_kb_item(name:kb_base+'lang', value:_mysql["lang"]);
  replace_kb_item(name:kb_base+'status', value:_mysql["status"]);

  return 1;
}

function mysql_close()
{
  if (!isnull(_mysql) && !isnull(_mysql["soc"])) close(_mysql["soc"]);
  _mysql = NULL;
}

function mysql_recv_packet()
{
  local_var hdr, pkt, soc;
  if (isnull(_mysql))
  {
    display("mysql_recv_packet: need to call mysql_init first.\n");
    return NULL;
  }

  # nb: open the socket if necessary.
  soc = mysql_get_socket();
  if (isnull(soc))
  {
    if (!mysql_open()) return NULL;
    soc = mysql_get_socket();
  }

  # Read the packet header.
  hdr = recv(socket:soc, length:4);
  if (strlen(hdr) != 4) return NULL;

  pkt["len"] = ord(hdr[0]) + (ord(hdr[1]) << 8) + (ord(hdr[2]) << 16);
  pkt["num"] = ord(hdr[3]);

  # And now the packet.
  pkt["data"] = recv(socket:soc, length:pkt["len"]);
  if (strlen(pkt["data"]) != pkt["len"]) return NULL;

  return pkt;
}

##
# Perform an SQL text query and receive and parse the results.
# CLIENT_PROTOCOL_41 only.
#
# @remark A collision of column name is an error case.
#
# @param sql The SQL to send to be executed.
# @param exit_on_fail Whether to exit in the case of failure.
#
# @return A list of associative arrays each representing a mapping between
#   column names and values. Values are represented as strings or NULL.
##
function mysql_query_41(sql, exit_on_fail)
{
  local_var column_defs, column_name, column_values, error, error_details,
    keyed_row, keyed_rows, i, msg, packet, row, rows, sent_bytes,
    sequence_id;

  sequence_id = 0;

  # Send the COM_QUERY which contains the SQL.
  sent_bytes = mysql_send_packet(
    data : mkbyte(SERVER_COMMAND_COM_QUERY) + sql,
    num  : sequence_id
  );

  if (isnull(sent_bytes))
    return _mysql_error(msg:"COM_QUERY failed to send.", exit_on_fail:exit_on_fail);

  # The column count packet.
  packet = mysql_recv_packet();
  sequence_id++;
  if (isnull(packet))
  {
    return _mysql_error(
      msg          : "Failed to receive response to COM_QUERY.",
      exit_on_fail : exit_on_fail
    );
  }

  # Was there a packet that wasn't read?
  if (packet["num"] != sequence_id)
  {
    error = "Unexpected sequence ID when trying to receive response to COM_QUERY.";
    return _mysql_error(
      msg          : error,
      exit_on_fail : exit_on_fail
    );
  }

  # This should never happen, but it is a domain requirement of functions
  # we call later.
  if (packet["len"] < 1)
  {
    return _mysql_error(
      msg          : "Empty packet instead of expected response to COM_QUERY.",
      exit_on_fail : exit_on_fail
    );
  }

  if (mysql_is_error_packet(packet:packet))
  {
    msg = "Error packet in response to our COM_QUERY.";

    error_details = mysql_parse_error_packet(packet:packet);
    if (!isnull(error_details))
      msg += ": " + error_details["msg"];

    msg += ".";

    return _mysql_error(msg:msg, exit_on_fail:exit_on_fail);
  }

  # OK packet is a listed case, but I am unaware of which case it occurs in.
  # See https://dev.mysql.com/doc/internals/en/com-query-response.htm
  # Perhaps we can ignore this and just read columns until EOF is encountered,
  # but as this case has been unencountered, it can't be tested.
  if (mysql_is_ok_packet(packet:packet))
  {
    return _mysql_error(
      msg          : "Unexpected OK packet in response to our COM_QUERY.",
      exit_on_fail : exit_on_fail
    );
  }

  column_defs = mysql_recv_column_defs_41(exit_on_fail:exit_on_fail);
  if (isnull(column_defs))
  {
    return _mysql_error(
      msg          : "Unable to receive and parse column definitions.",
      exit_on_fail : exit_on_fail
    );
  }

  rows = mysql_recv_resultset_rows(
    column_count : max_index(column_defs),
    exit_on_fail : exit_on_fail
  );
  if (isnull(rows))
  {
   return _mysql_error(
      msg          : "Unable to receive and parse rows.",
      exit_on_fail : exit_on_fail
    );
  }

  # Generate a list of associative arrays representing each row.
  keyed_rows = make_list();
  foreach row (rows)
  {
    keyed_row = make_array();
    for (i = 0; i < max_index(row); i++)
    {
      # We know column_defs to be the same length as rows due to
      # the contract with mysql_recv_resultset_rows.
      column_name = column_defs[i]["name"];

      # Detect collisions.
      if (!isnull(keyed_row[column_name]))
      {
        return _mysql_error(
          msg          : "Column name collision in SQL query.",
          exit_on_fail : exit_on_fail
        );
      }

      keyed_row[column_name] = row[i];
    }

    keyed_rows[max_index(keyed_rows)] = keyed_row;
  }

  return keyed_rows;
}

##
# Receive column definitions until EOF is reached. CLIENT_PROTOCOL_41 only.
#
# @param exit_on_fail Whether to exit in the case of failure.
#
# @return A list of associative arrays representing each column.
#   These values follow the form of mysql_parse_column_def_41.
##
function mysql_recv_column_defs_41(exit_on_fail)
{
  local_var column_def, column_defs, packet;

  # Read column definitions until EOF is reached.
  column_defs = make_list();
  while (TRUE)
  {
    packet = mysql_recv_packet();
    if (isnull(packet))
    {
      return _mysql_error(
        msg          : "Failed to receive MySQL packet.",
        exit_on_fail : exit_on_fail
      );
    }

    # An EOF packet indicates the end of column definitions.
    if (mysql_is_eof_packet(packet:packet))
      break;

    # Parse the packet we got.
    column_def = mysql_parse_column_def_41(
      packet       : packet,
      exit_on_fail : exit_on_fail
    );
    if (isnull(column_def))
    {
      return _mysql_error(
        msg          : "Unable to parse column definition.",
        exit_on_fail : exit_on_fail
      );
    }

    column_defs[max_index(column_defs)] = column_def;
  }

  return column_defs;
}

##
# Parse a column definition packet, CLIENT_PROTOCOL_41.
#
# @remark For more information, see in http://www.nessus.org/u?362763af
#   The extra fields available for responses to COM_FIELD_LIST are ignored.
#
# @param packet The packet as received by _mysql_recv_packet().
# @param exit_on_fail Whether to exit on failure to parse.
#
# @return An associative array containing the following keys:
#    catalog       -- catalog (always "def")
#    schema        -- schema-name
#    table         -- virtual table-name
#    org_table     -- physical table-name
#    name          -- virtual column name
#    org_name      -- physical column name
#    next_length   -- length of the following fields (always 0x0c)
#    character_set -- is the column character set and is defined in Protocol::CharacterSet.
#    column_length -- maximum length of the field
#    column_type   -- type of the column as defined in Column Type
#    flags         -- flags
#    decimals      -- max shown decimal digits
#        0x00 for integers and static strings
#        0x1f for dynamic strings, double, float
#        0x00 to 0x51 for decimals
##
function mysql_parse_column_def_41(packet, exit_on_fail)
{
  local_var catalog, command, def, key, length, next_length,
    next_length_lenc_int, stream;

  stream = stream_init(packet["data"]);
  def = make_array();

  foreach key (make_list("catalog", "schema", "table", "org_table", "name", "org_name"))
  {
    def[key] = mysql_stream_get_lenenc_str(stream);

    if (isnull(def[key])) {
      return _mysql_error(
        msg          : "Unable to read column definition field '" + key + "'.",
        exit_on_fail : exit_on_fail
      );
    }
  }

  # The number of bytes left to read.
  next_length_lenc_int = mysql_stream_get_lenenc_int(stream);
  if (isnull(next_length_lenc_int))
  {
    return _mysql_error(
      msg          : "Column definition ended before (or during) next_length.",
      exit_on_fail : exit_on_fail
    );
  }

  next_length = next_length_lenc_int["integer"];
  if (isnull(next_length) || next_length != 12)
  {
    return _mysql_error(
      msg          : "Unexpected value of next_length in column definition.",
      exit_on_fail : exit_on_fail
    );
  }

  # Length of character set (2), column length (1), type (1), flags (2),
  # decimals (1), and filler (2)
  if (stream_get_remaining_length(stream) < 12)
  {
    return _mysql_error(
      msg          : "Unexpected length of column definition.",
      exit_on_fail : exit_on_fail
    );
  }

  def["character_set"] = stream_get_data(stream, 2);
  def["column_length"] = stream_get_dword(stream);
  def["type"] = stream_get_data(stream, 1);
  def["flags"] = stream_get_data(stream, 2);
  def["decimals"] = stream_get_data(stream, 1);

  return def;
}

##
# Detects if provided packet is an EOF_Packet.
#
# @remark For more information, see https://dev.mysql.com/doc/internals/en/generic-response-packets.html#packet-EOF_Packet
#
# @param packet The potential EOF_Packet.
#
# @return Whether or not the packet is an EOF_Packet.
##
function mysql_is_eof_packet(packet)
{
  if (isnull(packet) || packet["len"] < 1)
  {
    display("mysql_is_eof_packet: 'packet' argument is missing or invalid.\n");
    return NULL;
  }

  return getbyte(blob:packet["data"], pos:0) == 0xfe;
}

##
# Reads a length encoded string (aka lenenc_str) from a stream_func.inc stream.
#
# @anonparam stream A stream returned by stream_init of stream_func.inc.
#
# @return String otherwise NULL if stream is too short, lenenc_int failed to
#   parse, lenenc_int was too long (> 3 bytes), or lenenc_int represented a
#   NULL value.
##
function mysql_stream_get_lenenc_str()
{
  local_var stream, lenenc_int, length;

  stream = _FCT_ANON_ARGS[0];

  lenenc_int = mysql_stream_get_lenenc_int(stream);

  if (isnull(lenenc_int) || isnull(lenenc_int["integer"])) return NULL;

  length = lenenc_int["integer"];

  if (length == 0) return "";

  return stream_get_data(stream, length);
}

##
# Receives ProtocolText::ResultsetRow packets until EOF is reached.
#
# @param column_count The number of columns per row.
# @param exit_on_fail Whether to exit in the event of failure.
#
# @return A list of lists, each representing a row parsed by
#    mysql_parse_resultset_row.
##
function mysql_recv_resultset_rows(column_count, exit_on_fail)
{
  local_var packet, row, rows;

  rows = make_list();
  while (TRUE)
  {
    packet = mysql_recv_packet();
    if (isnull(packet))
    {
      return _mysql_error(
        msg          : "Did not receive valid packet from MySQL server.",
        exit_on_fail : exit_on_fail
      );
    }

    # "In case the query could generate the column-definition, but generating
    # the rows afterwards failed, a ERR_Packet may be sent instead of the last
    # EOF_Packet. "
    if (mysql_is_error_packet(packet:packet))
    {
      return _mysql_error(
        msg          : "The MySQL server failed to generate rows.",
        packet       : packet,
        exit_on_fail : exit_on_fail
      );
    }

    if (mysql_is_eof_packet(packet:packet))
      break;

    row = mysql_parse_resultset_row(packet:packet, column_count:column_count);
    if (isnull(row))
    {
      return _mysql_error(
        msg          : "Unable to parse resultset row.",
        exit_on_fail : exit_on_fail
      );
    }

    rows[max_index(rows)] = row;
  }

  return rows;
}

##
# Parses a ProtocolText::ResultsetRow.
#
# @remark For more information, see https://dev.mysql.com/doc/internals/en/com-query-response.html#packet-ProtocolText::ResultsetRow
#
# @param packet The packet received from mysql_recv_packet().
# @param column_count The number of columns in the row.
#
# @return A list of values, one per column.
##
function mysql_parse_resultset_row(packet, column_count)
{
  local_var column, columns, i, stream;

  stream = stream_init(packet["data"]);

  columns = make_list();
  for (i = 0; i < column_count; i++)
  {
    if (stream_get_remaining_length(stream) < 1) return NULL;

    # NULL values are expected for NULL column values.
    column = mysql_stream_get_lenenc_str(stream);
    columns[max_index(columns)] = column;
  }

  return columns;
}

##
# Reads a length encoded integer (aka lenenc_int) from a stream_func.inc stream.
#
# @remark For more information, see http://www.nessus.org/u?49c06602
#
# @anonparam stream A stream returned by stream_init of stream_func.inc.
#
# @return NULL if stream is too short, otherwise an associative array containing
#   integer - The integer read. NULL if key "overflow" or "is_null" is set.
#   overflow - The integer was too large for NASL. Happens for 8 byte integer.
#   raw - The bytes that represented the integer.
#   is_null - The integer is NULL.
##
function mysql_stream_get_lenenc_int()
{
  local_var first_byte, number, raw, stream;

  stream = _FCT_ANON_ARGS[0];

  # There should be at least 1 byte available.
  if (stream_get_remaining_length(stream) < 1) return NULL;

  # The first byte indicates the nature of the integer.
  first_byte = stream_get_byte(stream);

  # "If it is < 0xfb, treat it as a 1-byte integer."
  if (first_byte < 0xfb)
  {
    return make_array("integer", first_byte, "raw", mkbyte(first_byte));
  }

  # "If it is 0xfb, it is represents a NULL in a ProtocolText::ResultsetRow."
  if (first_byte == 0xfb) return make_array("is_null", TRUE);

  # "If it is 0xfc, it is followed by a 2-byte integer."
  if (first_byte == 0xfc) {
    raw = stream_get_data(stream, 2);
    if (isnull(raw)) return NULL;

    return make_array("integer", getword(blob:raw, pos:0), "raw", raw);
  }

  # "If it is 0xfd, it is followed by a 3-byte integer."
  if (first_byte == 0xfd) {
    raw = stream_get_data(stream, 3);
    if (isnull(raw)) return NULL;

    # This library sets byte order to BYTE_ORDER_LITTLE_ENDIAN
    number =
      getword(blob:raw, pos:0) |
      getword(blob:raw, pos:1) << 8 |
      getword(blob:raw, pos:2) << 16;

    return make_array("integer", number, "raw", raw);
  }

  # "If it is 0xfe, it is followed by a 8-byte integer."
  if (first_byte == 0xfe) {
    raw = stream_get_data(stream, 8);
    if (isnull(raw)) return NULL;

    return make_array("overflow", TRUE, "raw", raw);
  }

  # "0xff as 1st byte of length-encoded integers is undefined."
  return NULL;
}

##
# Sends a payload to the MySQL server, prepending it with the
# MySQL packet header.
#
# @param data The payload.
# @param len The length of the payload, strlen(data) if undefined.
# @param num The sequence ID to use in the packet header.
#
# @return NULL on failure, otherwise length of data sent.
##
function mysql_send_packet(data, len, num)
{
  local_var soc;

  if (isnull(data))
  {
    display("mysql_send_packet: 'data' argument missing.\n");
    return NULL;
  }

  # nb: open the socket if necessary.
  soc = mysql_get_socket();
  if (isnull(soc))
  {
    if (!mysql_open()) return NULL;
    soc = mysql_get_socket();
  }

  if (isnull(len)) len = strlen(data);
  if (isnull(num)) num = 1;
  send(
    socket : soc,
    data   : raw_string(len & 0xff, (len >> 8) & 0xff, (len >> 16) & 0xff) +
             mkbyte(num) +
             data
  );
  return strlen(data) + 4;
}

##
# attempts to login to the MySQL server
#
# @remark using this function could pose a security risk. if the caller sets
#         the CLIENT_SSL flag in 'flags', this function sets it to zero before
#         attempting to connect to the server (it also does this for CLIENT_COMPRESS).
#         don't use this function if SSL is required
#
# @param user - username
# @param pass - password
# @param db - database to use after logging in
# @param flags - bitset of client capabilities
# @param max_pkt_sz - maximum packet size
# @param charset - character set
#
# @return TRUE if the login succeeded,
#         FALSE otherwise
##
function mysql_login(user, pass, db, flags, max_pkt_sz, charset)
{
  local_var cap, pkt, scramble, do_ssl, ssl_req, pkt_num;

  if (isnull(_mysql))
  {
    display("mysql_login: need to call mysql_init first.\n");
    return NULL;
  }
  if (isnull(user))
  {
    display("mysql_login: 'user' argument missing.\n");
    return NULL;
  }

  # just use what we need if we aren't passed in flags
  if (isnull(flags))
    flags = CLIENT_LONG_PASSWORD | CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION;
  if (isnull(max_pkt_sz)) max_pkt_sz = 0xFFFF;
  if (isnull(charset)) charset = mysql_get_lang();

  # We don't force SSL, only do SSL if it was specified in flags
  # and the server supports it.
  do_ssl = FALSE;
  if ((flags & CLIENT_SSL) == CLIENT_SSL) do_ssl = TRUE;
  if (do_ssl && !mysql_supports_ssl()) do_ssl = FALSE;

  # make sure the capabilities don't specify the use of compression,
  # though it would be nice to add support
  flags = flags & (0xFFFFFFFF - CLIENT_COMPRESS);

  if (empty_or_null(db))
    flags = flags & (0xFFFFFFFF - CLIENT_CONNECT_WITH_DB);
  else
    flags = flags | CLIENT_CONNECT_WITH_DB;

  if (empty_or_null(pass))
    flags = flags & (0xFFFFFFFF - CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA - CLIENT_PLUGIN_AUTH);
  else
    flags = flags | CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA | CLIENT_PLUGIN_AUTH;

  if (!do_ssl)
    flags = flags & (0xFFFFFFFF - CLIENT_SSL);

  cap =
    mkdword(flags) +                       # client capabilities
    mkdword(max_pkt_sz) +                  # max packet size
    mkbyte(charset) +                      # charset
    crap(data:raw_string(0), length:23) +  # filler
    user + mkbyte(0);

  if(flags & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA)
  {
    # TO DO.
    #
    # nb: this works for the 4.1 protocol, but only if the server doesn't
    # fallback to the older scheme.
    if (mysql_is_proto41_supported())
      scramble = mysql_get_scramble(pass:pass, msg:mysql_get_salt());
    else
      scramble = mysql_get_scramble323(pass:pass, msg:mysql_get_salt(), proto:10);
    if (strlen(scramble))
      cap += mkbyte(strlen(scramble)) + scramble;
  }

  else cap += mkbyte(0);

  if (flags & CLIENT_CONNECT_WITH_DB)
    cap += db + mkbyte(0);

  if (flags & CLIENT_PLUGIN_AUTH)
    cap += "mysql_native_password" + mkbyte(0);

  pkt_num = 1;
  # setup SSL
  if(do_ssl)
  {

    # this message counts as packet number one, so the next message
    # will be packet number two. mysql_recv_packet() won't get called
    # (which usually sets pkt["num"]) before sending our next packet,
    # so we have to specify it manually
    pkt_num = 2;

    # Protocol::SSLRequest packet
    ssl_req =
      mkdword(flags) +                       # client capabilities
      mkdword(max_pkt_sz) +                  # max packet size
      mkbyte(charset) +                      # charset
      crap(data:raw_string(0), length:23);   # filler

    # send ssl request packet before negotiating socket
    mysql_send_packet(data:ssl_req, len:strlen(ssl_req));

    # does mysql support any other encaps?
    _mysql["soc"] = socket_negotiate_ssl(socket: _mysql["soc"], transport: ENCAPS_TLSv1);

    if(!_mysql["soc"])
    {
      # we don't have a packet to log as an error, so use display() like other places
      # in this library do
      display('Error establishing TLS connection with MySQL server on port ' + _mysql["port"] + '\n');
      return 0;
    }
  }

  mysql_send_packet(data:cap, len:strlen(cap), num:pkt_num);

  pkt = mysql_recv_packet();
  # Handle case of a 4.1 server with an older password table.
  if (pkt && (pkt["data"] == raw_string(0xfe)))
  {
    # NB: untested.
    scramble = mysql_get_scramble323(pass:pass, msg:mysql_get_salt(), proto:10) +
      mkbyte(0);
    mysql_send_packet(data:scramble, num:pkt["num"]+1);
    pkt = mysql_recv_packet();
  }

  if (isnull(pkt) || mysql_is_error_packet(packet:pkt))
  {
    _mysql["err"] = pkt;
    return 0;
  }
  else return 1;
}

function mysql_get_socket()
{
  if (isnull(_mysql))
  {
    display("mysql_get_socket: need to call mysql_init first.\n");
    return NULL;
  }
  return _mysql["soc"];
}

function mysql_get_protocol()
{
  if (isnull(_mysql))
  {
    display("mysql_get_protocol: need to call mysql_init first.\n");
    return NULL;
  }
  return _mysql["proto"];
}


function mysql_get_version()
{
  if (isnull(_mysql))
  {
    display("mysql_get_version: need to call mysql_init first.\n");
    return NULL;
  }
  return _mysql["ver"];
}


function mysql_get_variant()
{
  local_var variant, ver;

  if (isnull(_mysql))
  {
    display("mysql_get_variant: need to call mysql_init first.\n");
    return NULL;
  }

  ver = mysql_get_version();
  if ("-enterprise-" >< ver) variant = "Enterprise Server";
  else if ("-MariaDB" >< ver) variant = "MariaDB";
  else if ("-cluster" >< ver) variant = "Cluster"; # MySQL Cluster
  else if (strlen(ver)) variant = "Community Server";
  else variant = NULL;

  return variant;
}

function is_mariadb()
{
  return mysql_get_variant() == 'MariaDB';
}

function mysql_get_thread_id()
{
  if (isnull(_mysql))
  {
    display("mysql_get_thread_id: need to call mysql_init first.\n");
    return NULL;
  }

  # nb: thread-id is connection-specific and thus not cached.
  if (isnull(mysql_get_socket()))
  {
    if (!mysql_open()) return NULL;
  }

  return _mysql["thread_id"];
}


function mysql_get_salt(bits)
{
  if (isnull(_mysql))
  {
    display("mysql_get_salt: need to call mysql_init first.\n");
    return NULL;
  }

  # nb: salt is connection-specific and thus not cached.
  if (isnull(mysql_get_socket()))
  {
    if (!mysql_open()) return NULL;
  }

  if (mysql_is_proto41_supported() && (isnull(bits) || bits == 20))
    return string(_mysql["salt"], _mysql["salt2"]);
  else
    return _mysql["salt"];
}

function mysql_get_caps()
{
  if (isnull(_mysql))
  {
    display("mysql_get_caps: need to call mysql_init first.\n");
    return NULL;
  }
  return _mysql["caps"];
}

function mysql_get_lang()
{
  if (isnull(_mysql))
  {
    display("mysql_get_lang: need to call mysql_init first.\n");
    return NULL;
  }
  return _mysql["lang"];
}

function mysql_get_status()
{
  if (isnull(_mysql))
  {
    display("mysql_get_status: need to call mysql_init first.\n");
    return NULL;
  }
  return _mysql["status"];
}

function mysql_is_proto41_supported()
{
  if (isnull(_mysql))
  {
    display("mysql_is_proto41_supported: need to call mysql_init first.\n");
    return NULL;
  }

  if (mysql_get_caps() & CLIENT_PROTOCOL_41) return TRUE;
  else return FALSE;
}

function mysql_is_ok_packet(packet)
{
  if (isnull(packet) || packet["len"] < 1)
  {
    display("mysql_is_ok_packet: 'packet' argument is missing or invalid.\n");
    return NULL;
  }
  if (getbyte(blob:packet["data"], pos:0) == 0) return TRUE;
  else return FALSE;
}

function mysql_is_error_packet(packet)
{
  if (isnull(packet) || packet["len"] < 1)
  {
    display("mysql_is_error_packet: 'packet' argument is missing or invalid.\n");
    return NULL;
  }
  if (getbyte(blob:packet["data"], pos:0) == 0xff) return TRUE;
  else return FALSE;
}

function mysql_get_null_string(blob, pos)
{
  local_var i, tmp;

  if (isnull(pos)) pos = 0;

  tmp = NULL;
  for (i=pos; i<strlen(blob); i++)
  {
    if (ord(blob[i]) != 0)
      tmp += blob[i];
    else
      break;
  }
  return tmp;
}

function mysql_get_last_error()
{
  if (isnull(_mysql))
  {
    display("mysql_get_last_error: need to call mysql_init first.\n");
    return NULL;
  }

  if (isnull(_mysql["err"])) return NULL;
  else return mysql_parse_error_packet(packet:_mysql["err"]);
}

# Returns TRUE if remote server uses SSL
function mysql_supports_ssl()
{
  if (isnull(_mysql))
  {
    display("mysql_get_last_error: need to call mysql_init first.\n");
    return NULL;
  }

  return (_mysql["caps"] & CLIENT_SSL);
}

function mysql_parse_error_packet(packet)
{
  local_var err;

  if (isnull(packet) || packet["len"] < 1)
  {
    display("mysql_parse_error_packet: 'packet' argument is missing or invalid.\n");
    return NULL;
  }

  err = NULL;
  if (mysql_is_error_packet(packet:packet))
  {
    err["num"] = getword(blob:packet["data"], pos:1);
    # Version 4.1.
    if (getbyte(blob:packet["data"], pos:3) == ord("#"))
    {
      err["state"] = substr(packet["data"], 4, 8);
      err["msg"] = substr(packet["data"], 9);
    }
    # Pre-version 4.1.
    else
    {
      err["state"] = NULL;
      err["msg"] = substr(packet["data"], 3);
    }
  }
  return err;
}

# nb: this function is used for 4.1 authentication.
function mysql_get_scramble(pass, msg)
{
  local_var i, l, scramble, stage1, stage2;

  if (isnull(pass))
  {
    display("mysql_get_scramble: 'pass' argument is missing.\n");
    return NULL;
  }
  if (isnull(msg))
  {
    display("mysql_get_scramble: 'msg' argument is missing.\n");
    return NULL;
  }

  stage1 = SHA1(pass);
  stage2 = SHA1(stage1);
  scramble = SHA1(string(msg, stage2));
  l = strlen(scramble);
  for (i=0; i<l; i++)
    scramble[i] = raw_string(ord(stage1[i]) ^ ord(scramble[i]));
  return scramble;
}

# NB: this is not yet working -- seed calculation can overflow.
function mysql_get_scramble323(pass, msg, proto)
{
  local_var extra, hash_msg, hash_pass, i, l, max_value, scramble, seed1, seed2;

  if (isnull(pass))
  {
    display("mysql_get_scramble323: 'pass' argument is missing.\n");
    return NULL;
  }
  if (isnull(msg))
  {
    display("mysql_get_scramble323: 'msg' argument is missing.\n");
    return NULL;
  }
  if (isnull(proto))
  {
    display("mysql_get_scramble323: 'proto' argument is missing.\n");
    return NULL;
  }

  scramble = "";
  l = strlen(pass);
  if (l && strlen(msg))
  {
    hash_pass = mysql_hash_password(pass:pass);
    hash_msg  = mysql_hash_password(pass:msg);

    if (proto == 10)
    {
      max_value = 0x3FFFFFFF;
      seed1 = (hash_pass[0] ^ hash_msg[0]) % max_value;
      seed2 = (hash_pass[1] ^ hash_msg[1]) % max_value;
    }
    else
    {
      max_value = 0x01FFFFFF;
      seed1 = (hash_pass[0] ^ hash_msg[0]) % max_value;
      seed2 = int(seed1/2);
    }

    for (i=0; i<=l; i++)
    {
      # NB: this overflows
      seed1 = int(seed1*3 + seed2) % max_value;
      seed2 = int(seed1 + seed2 + 33) % max_value;
      scramble += raw_string(int(seed1 / (max_value/31)) + 64);
    }
    if (proto == 10)
    {
      seed1 = int(seed1*3 + seed2) % max_value;
      seed2 = int(seed1 + seed2 + 33) % max_value;
      extra = int((seed1 / max_value)*31);

      for (i=0; i<l; i++)
        scramble[i] = raw_string(ord(scramble[i]) ^ extra);
    }
  }
  return scramble;
}

function mysql_hash_password(pass)
{
  local_var add, i, l, nr, nr2, result, tmp;

  if (isnull(pass))
  {
    display("mysql_hash_password: 'pass' argument is missing.\n");
    return NULL;
  }

  nr = 1345345333;
  add = 7;
  nr2 = 0x12345671;

  l = strlen(pass);
  for (i=0; i<l; i++)
  {
    tmp = ord(pass[i]);
    if (tmp != ' ' && tmp != '\t')
    {
      nr = nr ^ (((nr & 63) + add) * tmp)+ (nr << 8);
      nr2 += (nr2 << 8) ^ nr;
      add += tmp;
    }
  }
  result[0] = nr & ((1 << 31) -1);
  result[1] = nr2 & ((1 << 31) -1);

  return result;
}

##
# Exit with specified message if appropriate, otherwise return specified value.
#
# @param msg The message to exit with if exit_on_fail
# @param exit_on_fail Whether to exit.
# @param ret The value to return if we do not exit.
# @param packet The error packet, if it was encountered.
#
# @return The value of ret.
##
function _mysql_error(msg, ret, packet, exit_on_fail)
{
  if (exit_on_fail) exit(1, msg);

  if (!isnull(packet)) _mysql["err"] = packet;

  return ret;
}

##
# @param port Server port to pull info for
# @return A list of arrays containing credentials
##
function mysql_get_cred_combos_from_kb(port)
{
  local_var user, pass, dbtype, db_port, creds, idx, key, sets;

  creds = make_list();
  idx    = 0;
  sets   = 0;
  key    = "Database";
  dbtype = get_kb_item(key+"/type");
  db_port = get_kb_item(key+"/Port");

  while(!isnull(dbtype))
  {
    if(dbtype == 2 && port == db_port)
    {
      user         = get_kb_item(key+"/login");
      pass         = get_kb_item("/tmp/"+key+"/password");
      creds[sets++] = make_array(
        "login"       , user,
        "password"    , pass
      );
    }
    idx += 1;
    key = "Database/"+idx;
    dbtype = get_kb_item(key+"/type");
    db_port = get_kb_item(key+"/Port");
  }
  return creds;
}
