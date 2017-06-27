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
# torture_cgi_sql_inj_msg.inc
# $Revision: 1.15 $
#

global_var	global_patterns, sql_error_patterns;

i = 0;
sql_error_patterns[i++] = "ST:Column count doesn't match value count at row";
sql_error_patterns[i++] = "ST:error '80040e14";
sql_error_patterns[i++] = "ST:Incorrect column name";
sql_error_patterns[i++] = "ST:Incorrect column specifier for column";
sql_error_patterns[i++] = "ST:Invalid parameter type";
sql_error_patterns[i++] = "ST:Microsoft OLE DB Provider for";
sql_error_patterns[i++] = "ST:ODBC Microsoft Access Driver";
sql_error_patterns[i++] = "ST:[Microsoft][Driver ODBC Microsoft Access]";
sql_error_patterns[i++] = "ST:ODBC SQL Server Driver";
sql_error_patterns[i++] = "ST:supplied argument is not a valid MySQL result";
sql_error_patterns[i++] = "ST:mysql_query()";
sql_error_patterns[i++] = "ST:Unknown table";
sql_error_patterns[i++] = "ST:You have an error in your SQL syntax";
sql_error_patterns[i++] = "ST:[IBM][CLI Driver][DB2/6000]";
sql_error_patterns[i++] = "ST:not a valid MySQL result resource";
sql_error_patterns[i++] = "ST:unexpected end of SQL command";
sql_error_patterns[i++] = "ST:mySQL error with query";
sql_error_patterns[i++] = "ST:ADODB.Recordset";
sql_error_patterns[i++] = "ST:Unclosed quotation mark before the character string";
sql_error_patterns[i++] = "ST:Incorrect syntax near";
sql_error_patterns[i++] = "ST:PostgreSQL query failed:";
sql_error_patterns[i++] = "ST:not a valid PostgreSQL result";
sql_error_patterns[i++] = "ST:An illegal character has been found in the statement";
sql_error_patterns[i++] = "ST:SQLSTATE:";
sql_error_patterns[i++] = "ST:SQL command not properly ended";
sql_error_patterns[i++] = "ST:[SQL Server";
sql_error_patterns[i++] = "ST:[ODBC SQL";
sql_error_patterns[i++] = "ST:on MySQL result index";
# From torturecgis.nasl
sql_error_patterns[i++] = "ST:MySQL query";
# MA 2008-05-06: I saw that on Tomcat.
sql_error_patterns[i++] = "ST:Unexpected end of command in statement";
sql_error_patterns[i++] = "ST:System.Data.OleDb.OleDbException:";
sql_error_patterns[i++] = "ST:System.Data.SqlClient.SqlException:";

# -933ORA-00933: SQL command not properly ended
# PLS-00306: wrong number or types of arguments in call to '...'
sql_error_patterns[i++] = "RE:(ORA|PLS)-[0-9]{5}[^0-9]";
sql_error_patterns[i++] = "RE:ODBC Error Code.*=.*[a-zA-Z]+[0-9]+";
# MA 2009-05-19
sql_error_patterns[i++] = "RE:[sS]yntax error (.* )?in query expression";
# MA 2009-02-17: MS SQL - Should only happen with UNION SELECT...
sql_error_patterns[i++] = "RE:Msg [0-9]+, Level [0-9]+, State [0-9]+, Line [0-9]+";
sql_error_patterns[i++] = "PA:*Syntax error converting the * value * to a column of data type *";
sql_error_patterns[i++] = "ST:All queries in an SQL statement containing a UNION operator must have an equal number of expressions in their target lists";
# MySQL
sql_error_patterns[i++] = "ST:The used SELECT statements have a different number of columns";
sql_error_patterns[i++] = "PA:*Unknown column '*' in 'order clause'*";
sql_error_patterns[i++] = 'RE:ERROR [0-9]{4} \\([A-Z0-9]{5}\\):';
# MS SQL
sql_error_patterns[i++] = "PA:*Procedure * expects parameter * which was not supplied*";
#
sql_error_patterns[i++] = "ST:mysql_close()";
sql_error_patterns[i++] = "PA:*Erro ao gravar dados*UPDATE * SET * WHERE *";
sql_error_patterns[i++] = "ST:com.mysql.jdbc.exceptions.jdbc4.MySQLSyntaxErrorException:";
sql_error_patterns[i++] = "PA:*Table * not existing in database*";
# Postgres on a French system
sql_error_patterns[i++] = "ST:org.postgresql.util.PSQLException: ERREUR: erreur de syntaxe sur ou pr";
sql_error_patterns[i++] = "ST:org.postgresql.util.PSQLException: ERROR: syntax error at or near ";
# Postgres
sql_error_patterns[i++] = "RE:ERROR:.+(unterminated quoted (string|identifier)|syntax error) at or near.+"; 

# Potential FPs
if (report_paranoia >= 2 && ! get_kb_item("Settings/PCI_DSS") )
{
sql_error_patterns[i++] = "ST:Unable to connect to PostgreSQL server:";
sql_error_patterns[i++] = "ST:Can't connect to local";
sql_error_patterns[i++] = "ST:mysql_connect(): Access denied";
sql_error_patterns[i++] = "ST:PL/SQL";	# Not precise enough
sql_error_patterns[i++] = "ST:org.postgresql.util.PSQLException: ERR";
# Seen with ColdFusion
sql_error_patterns[i++] = "ST:Error Occurred While Processing Request";
}

