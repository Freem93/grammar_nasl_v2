#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74242);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/06/16 17:06:58 $");

  script_cve_id("CVE-2014-0178", "CVE-2014-0239");
  script_bugtraq_id(67686, 67691);
  script_osvdb_id(107484, 107485);

  script_name(english:"Samba 4.x < 4.0.18 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Samba");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is potentially affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Samba running on the remote
host is 4.x prior to 4.0.18 and is, therefore, potentially affected by
the following vulnerabilities :

  - An error exists related to 'GET_SHADOW_COPY_DATA' or
    'FSCTL_SRV_ENUMERATE_SNAPSHOTS' request handling and
    'vfs objects' parameter configurations of 'shadow_copy'
    or 'shadow_copy2' that could allow disclosure of
    uninitialized memory contents. (CVE-2014-0178)

  - An error exists related to handling the 'reply' flag
    DNS packet headers that could allow denial of service
    attacks. (CVE-2014-0239)

Note that Nessus has relied only on the self-reported version number
and has not actually tried to exploit these issues or determine if the
associated patch has been applied.");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2014-0178.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2014-0239.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-4.0.18.html");
  # http://www.samba.org/samba/ftp/patches/security/samba-4.0.17-CVE-2014-0178-CVE-2014-0239.patch
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?da7865ef");
  script_set_attribute(attribute:"solution", value:
"Either install the patch referenced in the project's advisory, or
upgrade to 4.0.18 or later.

Alternatively, refer to the vendor advisories and apply the suggested
workarounds.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/30");

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

if (lanman =~ '^Samba 4(\\.0)?$') audit(AUDIT_VER_NOT_GRANULAR, "Samba", port, version);

version = lanman - 'Samba ';
ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] == 4 && ver[1] == 0 && ver[2] < 18)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version +
             '\n  Fixed version     : 4.0.18\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Samba", port, version);
