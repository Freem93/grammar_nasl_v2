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
# torture_cgi_err_msg.inc
# $Revision: 2.7 $
#

global_var	global_patterns, err_msg_patterns;

i = 0;
err_msg_patterns[i++] = "ST:<title>Runtime Error</title>";
err_msg_patterns[i++] = "RE:Server Error in '[^']*' Application\.";
err_msg_patterns[i++] = "ST:The current error page you are seeing can be replaced by a custom error page";
err_msg_patterns[i++] = "ST:>The following error occurred<BR>";
err_msg_patterns[i++] = "PA:*Warning: * [*]: failed to *:* in * on line *";
err_msg_patterns[i++] = "PA:*Fatal error: error_sql :: INSERT command denied to user '*0'@'*' for table '*'*";
err_msg_patterns[i++] = "ST:Erro ao gravar dados";
err_msg_patterns[i++] = "RE:\[(NullReference|Http(Unhandled)?)Exception\]?:";
# MySQL
err_msg_patterns[i++] = "RE:Access denied for user '[^']+'@'[^']*' \(using password: .*\)";
# Pear (and others?)
err_msg_patterns[i++] = "ST:Fatal error: Call to undefined method ";
#
err_msg_patterns[i++] = "RE:<PRE> *java\.(lang|sql)\.(NumberFormatException|SQLException): ";
err_msg_patterns[i++] = "ST:at org.postgresql.jdbc2.AbstractJdbc2Statement.execute(";
