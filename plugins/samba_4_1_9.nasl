#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76202);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/06/16 17:06:58 $");

  script_cve_id("CVE-2014-0244", "CVE-2014-3493");
  script_bugtraq_id(68148, 68150);
  script_osvdb_id(108347, 108348);

  script_name(english:"Samba 3.6.x < 3.6.24 / 4.0.x < 4.0.19 / 4.1.x < 4.1.9 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Samba.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is affected by multiple denial of service
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Samba on the remote
host is 3.6.x prior to 3.6.24, 4.0.x prior to 4.0.19, or 4.1.x prior
to 4.1.9. It is, therefore, affected by the following vulnerabilities :

  - A denial of service flaw exists with 'nmbd'. A remote
    attacker, with a specially crafted packet, could
    cause the CPU to loop the same code segment, preventing
    further NetBIOS name services. (CVE-2014-0244)

  - A denial of service flaw exists with 'smbd' when an
    authenticated client makes a non-unicode request for a
    valid unicode path. An invalid return code from the
    conversion of bad unicode to Windows character set can
    cause memory at an offset from the expected return
    buffer to be overwritten. This could allow a remote
    authenticated attacker to cause a denial of service.
    (CVE-2014-3493)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2014-0244.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2014-3493.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-3.6.24.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-4.0.19.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-4.1.9.html");
  # http://ftp.samba.org/pub/samba/patches/security/samba-3.6.23-CVE-2014-0244-CVE-2014-3493.patch
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1034edf8");
  # http://ftp.samba.org/pub/samba/patches/security/samba-4.0.18-CVE-2014-0244-CVE-2014-3493.patch
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8989728b");
  # http://ftp.samba.org/pub/samba/patches/security/samba-4.1.8-CVE-2014-0244-CVE-2014-3493.patch
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?171a0ce4");
  script_set_attribute(attribute:"solution", value:
"Install the patch referenced in the project's advisory or upgrade to
3.6.24 / 4.0.19 / 4.1.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/NativeLanManager", "SMB/samba", "Settings/ParanoidReport");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

lanman = get_kb_item_or_exit("SMB/NativeLanManager");

if ("Samba " >!< lanman) audit(AUDIT_NOT_LISTEN, "Samba", port);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (
  lanman =~ '^Samba 3(\\.6)?$' ||
  lanman =~ '^Samba 4(\\.0)?$' ||
  lanman =~ '^Samba 4(\\.1)?$'
) audit(AUDIT_VER_NOT_GRANULAR, "Samba", port, version);

version = lanman - 'Samba ';
ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

fix = NULL;

if (ver[0] == 3 && ver[1] == 6 && ver[2] < 24) fix = '3.6.24';
if (ver[0] == 4 && ver[1] == 0 && ver[2] < 19) fix = '4.0.19';
if (ver[0] == 4 && ver[1] == 1 && ver[2] < 9) fix = '4.1.9';

if (fix)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version +
             '\n  Fixed version     : ' + fix + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Samba", port, version);
