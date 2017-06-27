#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52042);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2012/08/08 11:05:03 $");

  script_cve_id("CVE-2011-4922");
  script_bugtraq_id(46307);
  script_osvdb_id(72798);
  script_xref(name:"Secunia", value:"43271");

  script_name(english:"Pidgin < 2.7.10 Information Disclosure");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis", value:
"An instant messaging client installed on the remote Windows host is
affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:

"The version of Pidgin installed on the remote host is earlier than
2.7.10.  Such versions are potentially affected by an information
disclosure vulnerability because the application does not properly
clear certain data structures used in 'libpurple/cipher.c' prior to
freeing.  An attacker, exploiting this flaw, could potentially extract
partial information from memory regions freed by libpurple.");
 
  script_set_attribute(attribute:"see_also", value:"http://developer.pidgin.im/wiki/ChangeLog");
  script_set_attribute(attribute:"see_also", value:"http://www.pidgin.im/news/security/?id=50");
  script_set_attribute(attribute:"solution", value:"Upgrade to Pidgin 2.7.10 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2011/02/06");
  script_set_attribute(attribute:"patch_publication_date",value:"2011/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/21");

  script_set_attribute(attribute:"plugin_type", value:"local");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:pidgin:pidgin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2012 Tenable Network Security, Inc.");

  script_dependencies("pidgin_installed.nasl");
  script_require_keys("SMB/Pidgin/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/Pidgin/Version");
fixed_version = '2.7.10';

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  path = get_kb_item("SMB/Pidgin/Path");
  if (isnull(path)) path = 'n/a';
  port = get_kb_item("SMB/transport");

  if (report_verbosity > 0)
  {
    report =
      '\n  Install path       : ' + path +
      '\n  Installed version  : ' + version +
      '\n  Fixed version      : ' + fixed_version + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0, "Pidgin " + version + " is installed and hence not affected.");
