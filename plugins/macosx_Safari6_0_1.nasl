#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62216);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/20 14:12:05 $");

  script_cve_id(
    "CVE-2011-3105",
    "CVE-2012-2817",
    "CVE-2012-2818",
    "CVE-2012-2829",
    "CVE-2012-2831",
    "CVE-2012-2842",
    "CVE-2012-2843",
    "CVE-2012-3598",
    "CVE-2012-3601",
    "CVE-2012-3602",
    "CVE-2012-3606",
    "CVE-2012-3607",
    "CVE-2012-3612",
    "CVE-2012-3613",
    "CVE-2012-3614",
    "CVE-2012-3616",
    "CVE-2012-3617",
    "CVE-2012-3621",
    "CVE-2012-3622",
    "CVE-2012-3623",
    "CVE-2012-3624",
    "CVE-2012-3632",
    "CVE-2012-3643",
    "CVE-2012-3647",
    "CVE-2012-3648",
    "CVE-2012-3649",
    "CVE-2012-3651",
    "CVE-2012-3652",
    "CVE-2012-3654",
    "CVE-2012-3657",
    "CVE-2012-3658",
    "CVE-2012-3659",
    "CVE-2012-3660",
    "CVE-2012-3671",
    "CVE-2012-3672",
    "CVE-2012-3673",
    "CVE-2012-3675",
    "CVE-2012-3676",
    "CVE-2012-3677",
    "CVE-2012-3684",
    "CVE-2012-3685",
    "CVE-2012-3687",
    "CVE-2012-3688",
    "CVE-2012-3692",
    "CVE-2012-3699",
    "CVE-2012-3700",
    "CVE-2012-3701",
    "CVE-2012-3702",
    "CVE-2012-3703",
    "CVE-2012-3704",
    "CVE-2012-3705",
    "CVE-2012-3706",
    "CVE-2012-3707",
    "CVE-2012-3708",
    "CVE-2012-3709",
    "CVE-2012-3710",
    "CVE-2012-3711",
    "CVE-2012-3712",
    "CVE-2012-3713",
    "CVE-2012-3714",
    "CVE-2012-3715"
  );
  script_bugtraq_id(
    53679,
    54203,
    54386,
    54680,
    55534,
    55624,
    55625,
    55626
  );
  script_osvdb_id(
    82242,
    83238,
    83242,
    83256,
    83257,
    83727,
    83734,
    85365,
    85366,
    85367,
    85368,
    85369,
    85370,
    85371,
    85372,
    85373,
    85374,
    85375,
    85376,
    85377,
    85378,
    85379,
    85380,
    85381,
    85382,
    85384,
    85385,
    85386,
    85387,
    85388,
    85389,
    85390,
    85391,
    85392,
    85393,
    85394,
    85396,
    85397,
    85398,
    85399,
    85400,
    85401,
    85402,
    85403,
    85404,
    85405,
    85406,
    85407,
    85408,
    85409,
    85410,
    85411,
    85412,
    85413,
    85414,
    85415,
    85416,
    85652,
    85653,
    85655
  );

  script_name(english:"Mac OS X : Apple Safari < 6.0.1 Multiple Vulnerabilities");
  script_summary(english:"Check the Safari SourceVersion");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains a web browser that is affected by several
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Apple Safari installed on the remote Mac OS X host is
earlier than 6.0.1.  It is, therefore, potentially affected by several
issues :

  - A logic error in Safari's handling of the Quarantine
    attribute caused the safe mode not to be triggered on
    Quarantined files, which could lead to the disclosure
    of local file contents. (CVE-2012-3713)

  - A rare condition in the handling of Form Autofill could
    lead to the disclosure of information from the Address
    Book 'Me' card that was not included in the Autofill
    popover. (CVE-2012-3714)

  - A logic issue in the handling of HTTPS URLs in the
    address bar when pasting text could result in the
    request being sent over HTTP. (CVE-2012-3715)

  - Numerous issues exist in WebKit. (CVE-2011-3105 /
    CVE-2012-2817 / CVE-2012-2818 / CVE-2012-2829 /
    CVE-2012-2831 / CVE-2012-2842 / CVE-2012-2843 /
    CVE-2012-3598 / CVE-2012-3601 / CVE-2012-3602 /
    CVE-2012-3606 / CVE-2012-3607 / CVE-2012-3612 /
    CVE-2012-3613 / CVE-2012-3614 / CVE-2012-3616 /
    CVE-2012-3617 / CVE-2012-3621 / CVE-2012-3622 /
    CVE-2012-3623 / CVE-2012-3624 / CVE-2012-3632 /
    CVE-2012-3643 / CVE-2012-3647 / CVE-2012-3648 /
    CVE-2012-3649 / CVE-2012-3651 / CVE-2012-3652 /
    CVE-2012-3654 / CVE-2012-3657 / CVE-2012-3658 /
    CVE-2012-3659 / CVE-2012-3660 / CVE-2012-3671 /
    CVE-2012-3672 / CVE-2012-3673 / CVE-2012-3675 /
    CVE-2012-3676 / CVE-2012-3677 / CVE-2012-3684 /
    CVE-2012-3685 / CVE-2012-3687 / CVE-2012-3688 /
    CVE-2012-3692 / CVE-2012-3699 / CVE-2012-3700 /
    CVE-2012-3701 / CVE-2012-3702 / CVE-2012-3703 /
    CVE-2012-3704 / CVE-2012-3705 / CVE-2012-3706 /
    CVE-2012-3707 / CVE-2012-3708 / CVE-2012-3709 /
    CVE-2012-3710 / CVE-2012-3711 / CVE-2012-3712)"
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5502");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2012/Sep/msg00005.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple Safari 6.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_Safari31.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Safari/Installed");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

if (!ereg(pattern:"Mac OS X 10\.[78]([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.7 / 10.8");


get_kb_item_or_exit("MacOSX/Safari/Installed");
path = get_kb_item_or_exit("MacOSX/Safari/Path", exit_code:1);
version = get_kb_item_or_exit("MacOSX/Safari/Version", exit_code:1);

fixed_version = "6.0.1";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Safari", version);
