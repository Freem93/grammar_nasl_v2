#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("socketpair")) exit(0, "socketpair() not defined.");

include("compat.inc");

if (description)
{
  script_id(51893);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/12 14:46:30 $");

  script_cve_id("CVE-2008-7270");
  script_bugtraq_id(45254);
  script_osvdb_id(69655);

  script_name(english:"OpenSSL SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG Ciphersuite Disabled Cipher Issue");
  script_summary(english:"Tries to resume a session with a disabled cipher.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host allows the resumption of SSL sessions with a disabled 
cipher.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL on the remote host has been shown to allow the
use of disabled ciphers when resuming a session.  This means that an
attacker that sees (e.g.  by sniffing) the start of an SSL connection
can manipulate the OpenSSL session cache to cause subsequent 
resumptions of that session to use a disabled cipher chosen by the 
attacker.");

  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSL 0.9.8j or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/07");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("ssl_resume.nasl");
  script_require_keys("SSL/Resume/Disabled");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ssl_funcs.inc");

# Get the information for each resume, forking as necessary.
port = get_kb_item_or_exit("SSL/Resume/Disabled");
encaps = get_kb_list_or_exit("SSL/Resume/Disabled/" + port);
encaps = make_list(encaps);

# If the user doesn't want the details, let's stop right here.
if (report_verbosity == 0)
{
  security_warning(port);
  exit(0);
}

report = "";
foreach encap (sort(encaps))
{
  session_id = get_kb_item("SSL/Resume/Disabled/" + port + "/" + encap + "/Session_ID");
  old_cipher = get_kb_item("SSL/Resume/Disabled/" + port + "/" + encap + "/Initial");
  new_cipher = get_kb_item("SSL/Resume/Disabled/" + port + "/" + encap + "/Resumed");

  if (encap == ENCAPS_SSLv3)
    version = "SSLv3";
  else if (encap == ENCAPS_TLSv1)
    version = "TLSv1";
  else
    version = "Unknown";

  report +=
    '\nThe server allowed the following session over ' + version + ' to be resumed as follows :' +
    '\n' +
    '\n  Session ID     : ' + session_id +
    '\n  Initial Cipher : ' + old_cipher + " (0x" + hexstr(ciphers[old_cipher]) + ")" +
    '\n  Resumed Cipher : ' + new_cipher + " (0x" + hexstr(ciphers[new_cipher]) + ")" +
    '\n';
}

security_warning(port:port, extra:report);
