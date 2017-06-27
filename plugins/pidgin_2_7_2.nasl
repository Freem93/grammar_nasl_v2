#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(47802);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2011/04/13 20:24:24 $");

  script_cve_id("CVE-2010-2528");
  script_bugtraq_id(41881);
  script_osvdb_id(66506);
  script_xref(name:"Secunia", value:"40699");

  script_name(english:"Pidgin X-Status NULL Pointer Denial of Service");
  script_summary(english:"Does a version check");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An instant messaging client installed on the remote Windows host is
affected by a denial of service vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Pidgin installed on the remote host is 
earlier than 2.7.2.  Such versions have a denial of service
vulnerability when processing a malformed X-Status message 
due to a reference to a NULL pointer in the oscar protocol 
plugin."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.pidgin.im/news/security/?id=47"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Pidgin 2.7.2 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vuln_publication_date",value:"2010/07/21");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/07/21");
  script_set_attribute(attribute:"plugin_publication_date",value:"2010/07/22");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pidgin:pidgin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");

  script_dependencies("pidgin_installed.nasl");
  script_require_keys("SMB/Pidgin/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/Pidgin/Version");

# Versions < 2.7.2 are affected
res = ver_compare(ver: version, fix: '2.7.2', strict: FALSE);
if (res < 0)
{
  port = get_kb_item("SMB/transport");

  if(report_verbosity > 0)
  {
    report =
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 2.7.2\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0, "Version " + version + " is not affected.");

