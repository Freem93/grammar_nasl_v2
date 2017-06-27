#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(65668);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/05/10 19:18:33 $");

  script_cve_id("CVE-2013-7089", "CVE-2013-7087", "CVE-2013-7088");
  script_bugtraq_id(58546);
  script_osvdb_id(91443, 91444, 91730, 106317);

  script_name(english:"ClamAV < 0.97.7 Multiple Vulnerabilities");
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
remote host is earlier than 0.97.7 and is, therefore, potentially
affected by the following vulnerabilities :

  - A memory access error exists related to the function
    'check_user_password' and debug-printing that could
    access 32 bytes rather than the proper 16 bytes.
    (Issue 6804 / CVE-2013-7089)

  - A heap-corruption error exists in the function
    'wwunpack' in the file 'libclamav/wwunpack.c' related
    to unpacking 'WWPack' files. (Issue 6806 /
    CVE-2013-7087)

  - An unspecified overflow error exists related to 'y0da'
    emulation that could result in application crashes or
    other unspecified impact. (Issue 6809 / CVE-2013-7088)

  - A double-free error exists in the function
    'unrar_extract_next_prepare' in the file
    'libclamunrar_iface/unrar_iface.c' related to handling
    'RAR' files."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://blog.clamav.net/2013/03/clamav-0977-has-been-released.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/vrtadmin/clamav-devel/blob/master/ChangeLog"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.clamav.net/show_bug.cgi?id=6804"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.clamav.net/show_bug.cgi?id=6806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.clamav.net/show_bug.cgi?id=6809"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to ClamAV 0.97.7 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:clamav:clamav");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

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
#
# nb: versions like 0.94rc1 are possible.
ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  (ver[0] == 0 && ver[1] < 97) ||
  (ver[0] == 0 && ver[1] == 97 && ver[2] < 7)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 0.97.7\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "ClamAV", port, version);
