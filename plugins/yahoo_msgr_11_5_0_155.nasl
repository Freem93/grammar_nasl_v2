#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58000);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2012/02/20 11:52:56 $");

  script_cve_id("CVE-2012-0268");
  script_bugtraq_id(51405);
  script_osvdb_id(78292);
  script_xref(name:"Secunia", value:"47041");

  script_name(english:"Yahoo! Messenger < 11.5.0.155 CYImage::LoadJPG Method JPG File Handling Remote Integer Overflow");
  script_summary(english:"Checks version of Yahoo! Messenger"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The instant messaging application on the remote Windows host is
affected by an integer overflow vulnerability.");
 script_set_attribute(attribute:"description", value:
"The version of Yahoo! Messenger installed on the remote host is
earlier than 11.5.0.155 and is reportedly affected by an integer
overflow.  The error exists in the method 'CYImage::LoadJPG' in the
file 'YImage.dll'. 

A remote attacker could execute arbitrary code by tricking a user into
accepting a crafted JPG image that triggers the overflow. 

Note that the photo sharing functionality is not enabled by
default.");
  script_set_attribute(attribute:"solution", value:"Upgrade to Yahoo! Messenger version 11.5.0.155 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:yahoo:messenger");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("yahoo_installed.nasl");
  script_require_keys("SMB/Yahoo/Messenger/Version");

  exit(0);
}

include("global_settings.inc");
include('misc_func.inc');

port = get_kb_item("SMB/transport");

version = get_kb_item_or_exit('SMB/Yahoo/Messenger/Version');
install_path = get_kb_item_or_exit('SMB/Yahoo/Messenger/Path');

fixed_ver = '11.5.0.155';

# Ver compare
if (ver_compare(ver:version, fix:fixed_ver) == -1)
{
  if(report_verbosity > 0)
  {
    report = 
      '\n  Path              : ' + install_path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_ver +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The Yahoo Messenger "+version+" install in "+install_path+" is not affected.");
