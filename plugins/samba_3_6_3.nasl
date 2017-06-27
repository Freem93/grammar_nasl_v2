#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57752);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/14 20:22:11 $");

  script_cve_id("CVE-2012-0817");
  script_bugtraq_id(51713);
  script_osvdb_id(78651);

  script_name(english:"Samba 3.6.x < 3.6.3 Denial of Service");
  script_summary(english:"Checks version of Samba");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Samba 3.6.x running on the
remote host is earlier than 3.6.3. Errors exist in the files
'source3/lib/substitute.c' and 'sources3/smbd/server.c' that leak
small amounts of memory when processing every connection attempt.

An attacker can continually make connections to the server and cause a
denial of service attack against the affected smbd service.

Note that Nessus has not actually tried to exploit this issue or
otherwise determine if the patch has been applied.");
  script_set_attribute(attribute:"solution", value:
"Either install the patch referenced in the project's advisory or
upgrade to 3.6.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/security/CVE-2012-0817");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-3.6.3.html");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?448d861a");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/31");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/NativeLanManager", "SMB/samba", "Settings/ParanoidReport");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


if (report_paranoia < 2) audit(AUDIT_PARANOID);


port = get_kb_item("SMB/transport");


lanman = get_kb_item_or_exit("SMB/NativeLanManager");
if ("Samba " >!< lanman) exit(0, "The SMB service listening on port "+port+" is not running Samba.");
if (lanman =~ '^Samba 3(\\.6)?$') exit(1, "The version, "+lanman+", of the SMB service listening on port "+port+" is not granular enough to make a determination.");
if ("Samba 3.6" >!< lanman) exit(0, "The SMB service listening on port "+port+" is not running Samba 3.6.x.");

version = lanman - 'Samba ';
ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] == 3 && ver[1] == 6 && ver[2] < 3)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version  : ' + version +
             '\n  Fixed version      : 3.6.3\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, 'The Samba '+version+' install listening on port '+port+' is not affected.');
