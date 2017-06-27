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
# torture_cgi_xpath_msg.inc
# $Revision: 2.1 $
#

global_var	global_patterns, xpath_error_patterns;

i = 0;
xpath_error_patterns[i++] = 'RE:System.Xml.XPath.XPathException:.* has an invalid token';
