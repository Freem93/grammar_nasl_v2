#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(66308);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/04 18:02:13 $");

  script_cve_id("CVE-2013-2020", "CVE-2013-2021");
  script_bugtraq_id(59434, 60118);
  script_osvdb_id(92692, 92834, 92835);

  script_name(english:"ClamAV < 0.97.8 Multiple Vulnerabilities");
  script_summary(english:"Checks response to a clamd VERSION command");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The antivirus service running on the remote host is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version, the ClamAV clamd antivirus daemon on the
remote host is earlier than 0.97.8 and is, therefore, potentially
affected by the following vulnerabilities :

  - An overflow condition exists in the 'getsisstring()'
    function in 'libclamav/sis.c' when handling SIS content.
    This flaw reportedly only affects GNU/Linux.
    (Issue 6808)

  - A heap overflow exists in the 'libclamav/pdf.c' when
    handling a specially crafted encrypted PDF file.  This
    flaw reportedly affects ClamAV 0.97.1 - 0.97.7 only.
    (Issue 7053)

  - A heap overflow exists in 'libclamav/pe.c' that is
    triggered when handling a specially crafted UPX-packed
    executable.  (Issue 7055)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/vrtadmin/clamav-devel/blob/0.97/ChangeLog"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.clamav.net/show_bug.cgi?id=6808"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.clamav.net/show_bug.cgi?id=7053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.clamav.net/show_bug.cgi?id=7055"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to ClamAV 0.97.8 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:clamav:clamav");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("clamav_detect.nasl");
  script_require_keys("Antivirus/ClamAV/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Antivirus/ClamAV/version");
port = get_service(svc:"clamd", default:3310, exit_on_fail:TRUE);

# nb: banner checks of open source software are prone to false-
#     positives so only run the check if reporting is paranoid.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Check the version number.
ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  (ver[0] == 0 && ver[1] < 97) ||
  (ver[0] == 0 && ver[1] == 97 && ver[2] < 8)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 0.97.8\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "ClamAV", port, version);
