#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74290);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/06/16 17:06:58 $");

  script_cve_id("CVE-2014-0178", "CVE-2014-0239");
  script_bugtraq_id(67686, 67691);
  script_osvdb_id(107484, 107485);

  script_name(english:"Samba 3.5.x / 3.6.x < 3.6.25 / 4.1.x < 4.1.8 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Samba.");


  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is potentially affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Samba running on the remote
host is 3.5.x or 3.6.x prior to 3.6.25 / 4.1.x prior to 4.1.8. It is,
therefore, potentially affected by the following vulnerabilities :

  - An error exists related to GET_SHADOW_COPY_DATA() and
    FSCTL_SRV_ENUMERATE_SNAPSHOTS() request handling in
    which the SRV_SNAPSHOT_ARRAY response field is not
    properly initialized. Therefore, configurations with
    'shadow_copy' or 'shadow-copy2' specified for the
    'vfs objects' parameter can allow the disclosure of
    uninitialized memory contents. (CVE-2014-0178)

  - A denial of service vulnerability exists due to the
    internal DNS server failing to check the 'reply' flag in
    DNS packet headers. A remote attacker, via a forged
    response packet that triggers a communication loop, can
    cause the consumption of CPU processing and bandwidth.
    (CVE-2014-0239)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2014-0178.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2014-0239.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-4.1.8.html");
  # http://ftp.samba.org/pub/samba/patches/security/samba-4.1.7-CVE-2014-0178-CVE-2014-0239.patch
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8bd97636");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Samba 3.6.25 / 4.1.8 or later. Alternatively, install the
patch or apply the workaround referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/03");

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

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_kb_item("SMB/transport");
if (!port) port = 445;

lanman = get_kb_item_or_exit("SMB/NativeLanManager");

if ("Samba " >!< lanman) audit(AUDIT_NOT_LISTEN, "Samba", port);

if (lanman =~ '^Samba 3(\\.[56])?$' || lanman =~ '^Samba 4(\\.1)?$')
  audit(AUDIT_VER_NOT_GRANULAR, "Samba", port, version);

version = lanman - 'Samba ';
ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Affected :
# 3.5.x / 3.6.x < 3.6.25
# 4.0.x         < 4.0.8
if (
  (ver[0] == 3 && ver[1] == 6 && ver[2] < 25) ||
  (ver[0] == 4 && ver[1] == 1 && ver[2] < 8)
)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version +
             '\n  Fixed version     : 3.6.25 / 4.1.8\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Samba", port, version);
