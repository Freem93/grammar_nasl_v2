#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(71993);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/01/16 16:51:57 $");

  script_cve_id("CVE-2013-5010", "CVE-2013-5011");
  script_bugtraq_id(64129, 64130);
  script_osvdb_id(101911, 101912);

  script_name(english:"Symantec Endpoint Protection Client < 11.0.7.4 / 12.1.2 (SYM14-001)");
  script_summary(english:"Checks SEP Client version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The version of Symantec Endpoint Protection Client installed on the
remote host is affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Symantec Endpoint Protection Client running on the
remote host is either 11.x prior to 11.0.7.4 or 12.x prior to 12.1.2
(RU2).  It is, therefore, affected by multiple security 
vulnerabilities :

  - The Application/Device Control in the SEP Client does
    not properly enforce custom policies, which could allow
    an attacker to circumvent policy restrictions in order
    to access files or directories on the remote host.
    (CVE-2013-5010)

  - The SEP Client is susceptible to a flaw caused by an
    unquoted search path, which could allow an attacker to
    gain elevated privileges via a crafted program in the
    %SYSTEMDRIVE% directory. (CVE-2013-5011)"
  );

  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20140109_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?04df6327");
  script_set_attribute(attribute:"solution", value:"Upgrade to 11.0.7.4 (11.x) / 12.1.2 RU2 (12.x) or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:endpoint_protection");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("savce_installed.nasl");
  script_require_keys("Antivirus/SAVCE/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

display_ver = get_kb_item_or_exit('Antivirus/SAVCE/version');

major_ver = split(display_ver, sep:'.', keep:FALSE);
major_ver = int(major_ver[0]);

fixed_ver = make_array(
  11, '11.0.7400.1398',
  12, '12.1.2015.2015'
);

if (ver_compare(ver:display_ver, fix:fixed_ver[major_ver], strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : '+ display_ver +
      '\n  Fixed version     : '+ fixed_ver[major_ver] + 
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Symantec Endpoint Protection Client', display_ver);
