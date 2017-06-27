# -*- Fundamental -*-
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# See the following licenses for details :
#  http://www.nessus.org/plugins/RegisteredFeed.pdf
#  http://www.nessus.org/plugins/TenableCommercial.pdf
#  http://www.nessus.org/plugins/DirectFeed.pdf
#  http://www.nessus.org/plugins/DirectFeedCommercial.pdf
#
#
# @NOGPL@
#
# torture_cgi_names.inc
# $Revision: 1.27 $
#

global_var	_torture_cgi_names;

function torture_cgi_name(code)
{

# Notes:
# All codes are not necessarily in use.
# Usually, every script uses a different code, but there are a few 
# exceptions with ACT_END scripts.

  if (isnull(_torture_cgi_names))
    _torture_cgi_names = make_array(
      "AC", "Common credentials",

      "BI", "XPath injection",
      "BB", "blind XPath injection",

      "CM", "cookie manipulation",

      "DD", "data disclosure",

      "EX", "arbitrary command execution",
      "ET", "arbitrary command execution (time based)",
      "EI", "arbitrary command execution (time based, intrusive)",
      "EC", "code injection",

      "FS", "format string",
      "F2", "format string (extended tests)",

      "HI", "header injection",

      "II", "SSI injection",
      "IH", "SSI injection (on HTTP headers)",

      "JR", "HTTP response splitting",

      "KD", "sensitive data",

      "LI", "LDAP injection",

      "OP", "buffer overflow (potential)",
      "O2", "buffer overflow (extended tests)",

      "PH", "unseen parameters",	# was called "hidden parameters"

      "QO", "on site request forgery",
      "QX", "cross site request forgery", 

      "RD", "uncontrolled redirection",

      "SI", "SQL injection",
      "SB", "blind SQL injection",
      "ST", "blind SQL injection (time based)",
      "S4", "blind SQL injection (4 requests)",
      "SH", "SQL injection (on HTTP headers)",
      "SC", "SQL injection (on HTTP cookies)",
      "S2", "SQL injection (2nd order)",
      "SN", "SQL injection (on parameters names)",
      "SL", "SQL injection on Login form",

      "TQ", "directory traversal (quick test)",
      "TD", "directory traversal",
      "TW", "directory traversal (write access)",
      "T2", "directory traversal (extended test)",

      "WL", "local file inclusion",
      "WR", "web code injection",

      "XD", "DOM XSS",
      "XS", "cross-site scripting (quick test)", 
      "X3", "cross-site scripting (extended patterns)", 
      "X2", "cross-site scripting (comprehensive test)",
      "XP", "persistent XSS", 
      "XH", "XSS (on HTTP headers)",
      "XN", "XSS (on parameters names)",
      "XI", "script injection",

      "YZ", "HTML injection", 
      "YY", "injectable parameter",	# Not a security flaw

      "ZI", "XML injection" );

  if (isnull(_torture_cgi_names[code])) return code;
  return  _torture_cgi_names[code];
}
