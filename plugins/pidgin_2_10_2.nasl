#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58410);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/16 14:22:06 $");

  script_cve_id("CVE-2011-4939", "CVE-2012-1178");
  script_bugtraq_id(52475, 52476);
  script_osvdb_id(80145, 80146);

  script_name(english:"Pidgin < 2.10.2 Multiple DoS");
  script_summary(english:"Does a version check");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An instant messaging client installed on the remote Windows host is
potentially affected by multiple denial of service vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Pidgin installed on the remote host is earlier than
2.10.2 and is potentially affected by the following issues :

  - A denial of service vulnerability (NULL pointer 
    dereference) in the 'pidgin_conv_chat_rename_user' 
    function in 'gtkconv.c'. Remote attackers can trigger 
    the vulnerability by performing certain types of 
    nickname changes while in an XMPP chat room. 
    (CVE-2011-4939)

  - The msn_oim_report_to_user function in oim.c allows 
    remote servers to cause an application crash by 
    sending an OIM message without UTF-8 encoding. 
    (CVE-2012-1178)"
  );
  script_set_attribute(attribute:"see_also", value:"http://developer.pidgin.im/ticket/14392");
  script_set_attribute(attribute:"see_also", value:"http://pidgin.im/news/security/?id=60");
  script_set_attribute(attribute:"see_also", value:"http://pidgin.im/news/security/?id=61");
  script_set_attribute(attribute:"see_also", value:"http://developer.pidgin.im/ticket/14884");
  script_set_attribute(attribute:"solution", value:"Upgrade to Pidgin 2.10.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pidgin:pidgin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("pidgin_installed.nasl");
  script_require_keys("SMB/Pidgin/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

path = get_kb_item_or_exit("SMB/Pidgin/Path");
version = get_kb_item_or_exit("SMB/Pidgin/Version");
fixed_version = '2.10.2';

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");

  if (report_verbosity > 0)
  {
    report =
      '\n  Path               : ' + path +
      '\n  Installed version  : ' + version +
      '\n  Fixed version      : ' + fixed_version + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0, "The Pidgin " + version + " install under '+path+' is not affected.");
