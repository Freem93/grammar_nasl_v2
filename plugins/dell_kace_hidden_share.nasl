#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(53493);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/05 16:01:12 $");

  script_cve_id("CVE-2011-1672");
  script_bugtraq_id(47172);
  script_xref(name:"CERT", value:"598700");
  script_osvdb_id(71882);

  script_name(english:"Dell KACE K2000 Appliance Hidden CIFS Fileshare Information Disclosure");
  script_summary(english:"Tries to connect to the 'peinst' share w/o authentication");

  script_set_attribute(attribute:"synopsis", value:
"The remote deployment appliance has an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Dell KACE K2000 appliance has an information disclosure
vulnerability. A hidden, read-only share named 'peinst' is used to
facilitate Windows deployments. This share is populated with pre- and
post-installation tasks, as well as deployment bootfiles and media
used for Windows network installs. This share allows anonymous access.

A remote, unauthenticated attacker could connect to this share,
allowing them to access sensitive data used during deployments (e.g.
local and/or domain administrator credentials).");
  script_set_attribute(attribute:"see_also", value:"http://www.kace.com/support/kb/index.php?action=artikel&cat=1&id=1104");
  # https://support.kace.com/packages/hd_attachments/1104470/K2000_34_ReleaseNotes_en-us.pdf
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7a694232"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to K2000 3.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:kace_k2000_systems_deployment_appliance");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/samba", "SMB/guest_enabled");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("audit.inc");

get_kb_item_or_exit('SMB/samba');
get_kb_item_or_exit('SMB/guest_enabled');

share = 'peinst';
port    =  kb_smb_transport();

if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(share:share);
if (rc != 1)
{
  NetUseDel();
  exit(0, "Can't connect to " + share + " share - the host is likely not affected.");
}

is_kace = FALSE;
root_files = NULL;

# just connecting to the share should be Good Enough...we'll only try to
# check if the listing looks correct when not paranoid
if (report_paranoia < 2)
{
  max_files = 15;
  i = 0;

  ret = FindFirstFile(pattern:"\*");
  while (!isnull(ret[1]) && i++ < max_files)
  {
    root_files += ret[1] + '\n';

    # look for a known directory, just to ensure we're looking at KACE
    if (ret[1] == 'winpe_build')
    {
      is_kace = TRUE;
      break;
    }
    ret = FindNextFile(handle:ret);
  }
}

NetUseDel();

if (report_paranoia < 2 && !is_kace) exit(0, 'The host is not affected.');

if (report_verbosity > 0 && !isnull(root_files))
{
  report =
    '\nNessus connected to the hidden share "' + share + '" and was able to\n' +
    'list some of its files, including :\n\n' +
    root_files;
  security_warning(port:port, extra:report);
}
else security_warning(port);
