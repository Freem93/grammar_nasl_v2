#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(67118);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/06/16 17:06:58 $");

  script_cve_id("CVE-2013-0454");
  script_bugtraq_id(58655);
  script_osvdb_id(91889);

  script_name(english:"Samba 3.6.x < 3.6.6 Remote Security Bypass");
  script_summary(english:"Checks version of Samba");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is affected by a remote security bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Samba 3.6.x running on the
remote host is earlier than 3.6.6, and as such, it is potentially
affected by a remote security bypass vulnerability because it fails to
properly enforce CIFS share attributes. 

This may allow a remote, authenticated attacker to write to read-only
shares, impact integrity related to oplock, locking, coherency, or
leases or leases attributes. 

Note that Nessus has not actually tried to exploit this issue or
otherwise determine if the patch or workaround has been applied.");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2013-0454.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-3.6.6.html");
  script_set_attribute(attribute:"solution", value:
"Either install the patch referenced in the project's advisory or
upgrade to 3.6.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/01");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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

if (lanman =~ '^Samba 3(\\.6)?$') exit(1, "The version, "+lanman+", of the SMB service listening on port "+port+" is not granular enough to make a determination.");


version = lanman - 'Samba ';
ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);


# 3.6
if (ver[0] == 3 && ver[1] == 6 && ver[2] < 6)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version +
             '\n  Fixed version     : 3.6.6\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Samba", port, version);
