#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69182);
  script_version("$Revision: 2.10 $");
  script_cvs_date("$Date: 2016/08/03 20:55:31 $");

  script_name(english:"Pulse Connect Secure Unsupported Version Detection");
  script_summary(english:"Checks for EOL.");

  script_set_attribute(attribute:"synopsis", value:
"An obsolete operating system is running on the remote host.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
Pulse Connect Secure (formerly known as Juniper IVE OS and Junos Pulse
Secure IVE OS) operating system on the remote host is no longer
supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://www.pulsesecure.net/support/eol/software/pulse-connect-secure");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Juniper IVE OS that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:ive_os");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Juniper/IVE OS/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# We use the EoE dates, as there will not be any patches
# generated beyond this date.
latest = 'N/A. Product is no longer supported.';
eol = make_array(
#  "8.2", "2017/07/11",
#  "8.1", "2016/12/18",
  "8.0", "2015/09/30",
  "7.4", "2014/08/19",
  "7.3", "2014/04/05",
  "7.2", "2013/09/28",
  "7.1", "2012/11/14",
  "7.0", "2011/12/15",
  "6.5", "2011/06/24",
  "6.4", "2010/09/23",
  "6.3", "2010/03/16",
  "6.2", "2009/12/09",
  "6.1", "2009/10/04",
  "6.0", "2009/02/15",
  "5.5", "2008/10/16",
  "5.4", "2008/05/30",
  "5.3", "2007/08/27",
  "5.2", "2007/05/14",
  "5.1", "2007/02/08",
  "5.0", "2006/11/30",
  "4.2", "2006/02/27",
  "4.1", "2005/12/28",
  "4.0", "2005/08/16",
  "3.3", "2005/06/30",
  "3.2", "2005/01/28",
  "3.1", "2004/10/08",
  "3.0", "2004/06/05",
  "2.3", "2004/05/14",
  "2.2", "2004/03/30",
  "2.1", "2004/01/22",
  "2.0", "2003/12/07",
  "1.4", "2003/10/01",
  "1.3", "2003/09/04",
  "1.2", "2003/07/03",
  "1.1", "2003/06/12",
  "1.0", "2003/05/19"
);

version = get_kb_item_or_exit('Host/Juniper/IVE OS/Version');
match = eregmatch(string:version, pattern:'^([0-9.]+)([^0-9]|$)');

if (isnull(match)) exit(1, 'Error parsing version : ' + version);
release = match[1];

# version 0.x isn't listed on Juniper's EOL page but if it exists it's presumably unsupported

if (version =~ '^0\\.')
  eol_date = 'unknown';
else
  eol_date = eol[release];

if (isnull(eol_date)) audit(AUDIT_INST_VER_NOT_VULN, 'IVE OS', version);

set_kb_item(name:"Host/Juniper/IVE OS/unsupported", value:TRUE);

register_unsupported_product(product_name:"Juniper IVE OS", cpe_class:CPE_CLASS_OS,
                             cpe_base:"juniper:ive_os", version:tolower(version));

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + version +
    '\n  IVE OS ' + release + ' EOL date : ' + eol_date +
    '\n  Latest IVE OS version : ' + latest +
    '\n  EOL URL               : https://www.pulsesecure.net/support/eol/software/pulse-connect-secure\n';
  security_hole(port:0, extra:report);
}
else security_hole(0);
