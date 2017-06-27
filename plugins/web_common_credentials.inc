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
# web_common_credentials.inc
# $Revision: 1.7 $


global_var	nc, user, pass;

function mk_list(nc, prevl)
{
  local_var	j, h, l, n;

  h = make_array();
  n = 0;
  foreach j (make_list(prevl))
    if (! h[j])
    {
      h[j] = 1;
      l[n++] = j;
    }
  for (j = 0; j < nc; j ++)
    if (! h[j])
     l[n++] = j;
  return l; 
}


nc = 0;

user[nc] = "";			pass[nc++] = "admin";
user[nc] = "";			pass[nc++] = "password";
user[nc] = "";			pass[nc++] = "0";
user[nc] = "";			pass[nc++] = "1234";
user[nc] = "";			pass[nc++] = "12345";

user[nc] = "admin";		pass[nc++] = "";
user[nc] = "admin";		pass[nc++] = "admin";        # OSVDB 99265 and others.
user[nc] = "admin";		pass[nc++] = "secure";
user[nc] = "admin";		pass[nc++] = "palosanto";    # OSVDB 99265 / http://dariusfreamon.wordpress.com/2013/11/01/elastix-pbx-default-credentials/
user[nc] = "admin";		pass[nc++] = "pass";         # OSVDB 93015 / https://www.redteam-pentesting.de/en/advisories/rt-sa-2013-001/-exim-with-dovecot-typical-misconfiguration-leads-to-remote-command-execution
user[nc] = "admin";		pass[nc++] = "mypassword";   # OSVDB 99265 / http://dariusfreamon.wordpress.com/2013/11/01/elastix-pbx-default-credentials/
user[nc] = "admin";		pass[nc++] = "password";     # OSVDB 99265 / 99338
user[nc] = "admin";		pass[nc++] = "operator";
user[nc] = "admin";		pass[nc++] = "0";
user[nc] = "admin";		pass[nc++] = "1234";
user[nc] = "admin";		pass[nc++] = "1111";
user[nc] = "admin";		pass[nc++] = "2222";

user[nc] = "anonymous";		pass[nc++] = "anonymous";    # OSVDB 92262 / http://dariusfreamon.wordpress.com/2013/04/11/electro-industries-gaugetech-multiple-vulnerabilities/

user[nc] = "USER";		pass[nc++] = "USER";         # OSVDB 100729 / http://dariusfreamon.wordpress.com/2013/12/08/schneider-modicon-m340-for-ethernet-multiple-default-credentials/

user[nc] = "root";		pass[nc++] = "root";
user[nc] = "root";		pass[nc++] = "";
user[nc] = "root";		pass[nc++] = "pass";
user[nc] = "root";		pass[nc++] = "1234";

user[nc] = "default"; pass[nc++] = "default";       # https://dariusfreamon.wordpress.com/2015/04/21/omron-ns-series-programmable-terminals-web-interface-default-credentials/
