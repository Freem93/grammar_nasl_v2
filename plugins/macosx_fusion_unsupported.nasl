#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55851);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/07/27 13:57:36 $");

  script_name(english:"VMware Fusion Unsupported Version Detection");
  script_summary(english:"Checks if a VMware Fusion version is unsupported.");

  script_set_attribute(attribute:"synopsis", value:
"An unsupported version of virtualization software is installed on the
remote host.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
VMware Fusion on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  # http://www.vmware.com/support/policies/lifecycle/general/index.html#policy_fusion
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?785cb9aa");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of VMware Fusion that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:fusion");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_fusion_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Fusion/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);


os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");


version = get_kb_item_or_exit("MacOSX/Fusion/Version");

eos_dates = make_array(
  '7', 'March 3, 2016',
  '6', 'September 4, 2015',
  '5', 'August 23, 2014',
  '4', 'September 14, 2013',
  '3', 'October 27, 2011',
  '2', 'October 1, 2011',
  '1', 'March 12, 2010'
);
supported_versions = '8.x';


ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);
version_highlevel = ver[0];

foreach v (keys(eos_dates))
{
  if (v == version_highlevel)
  {
    register_unsupported_product(product_name:'VMWare Fusion',
                                 version:version, cpe_base:"vmware:fusion");

    if (report_verbosity > 0)
    {
      report +=
        '\n  Installed version    : ' + version +
        '\n  Supported version(s) : ' + supported_versions +
        '\n';
      security_hole(port:0, extra:report);
    }
    else security_hole(0);
    exit(0);
  }
}

exit(0, 'The VMware Fusion '+version_highlevel+'.x install is currently supported.');
