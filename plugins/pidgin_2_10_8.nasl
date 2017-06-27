#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72282);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/05/20 02:50:46 $");

  script_cve_id(
    "CVE-2012-6152",
    "CVE-2013-6477",
    "CVE-2013-6478",
    "CVE-2013-6479",
    "CVE-2013-6481",
    "CVE-2013-6482",
    "CVE-2013-6483",
    "CVE-2013-6484",
    "CVE-2013-6485",
    "CVE-2013-6486",
    "CVE-2013-6487",
    "CVE-2013-6489",
    "CVE-2013-6490",
    "CVE-2014-0020"
  );
  script_bugtraq_id(
    65188,
    65189,
    65192,
    65195,
    65243,
    65492
  );
  script_osvdb_id(
    102614,
    102615,
    102616,
    102617,
    102618,
    102619,
    102620,
    102621,
    102622,
    102623,
    102624,
    102625,
    102626,
    102627,
    102628,
    102629,
    102734
  );

  script_name(english:"Pidgin < 2.10.8 Multiple Vulnerabilities");
  script_summary(english:"Performs a version check.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An instant messaging client installed on the remote Windows host is
affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Pidgin installed on the remote host is a version prior
to 2.10.8. It is, therefore, potentially affected by the following
vulnerabilities :

  - The bundled version of Pango has an error that can lead
    to an application crash when rendering fonts and
    attempting to display certain Unicode characters. 

  - Errors exist related to handling unspecified
    characters, incorrect character encoding, incorrect
    XMPP timestamps, hovering a pointer over a long URL,
    unspecified HTTP responses, Yahoo! P2P messages, STUN
    responses, and IRC arguments that could cause
    application crashes and denial of service conditions.
    (CVE-2012-6152, CVE-2013-6477, CVE-2013-6478,
    CVE-2013-6479, CVE-2013-6481, CVE-2013-6484,
    CVE-2014-0020)

  - Errors exist related to handling MSN SOAP, MSN OIM, and
    MSN header content that could cause application
    crashes when NULL pointers are dereferenced.
    (CVE-2013-6482)

  - An error exists related XMPP content such that the
    'from' portion of some 'iq' replies is not verified.
    (CVE-2013-6483)

  - Errors exist related to parsing chunked and
    Gadu-Gadu HTTP content, MXit emoticons, and
    SIMPLE headers that could allow buffer overflows.
    (CVE-2013-6485, CVE-2013-6487, CVE-2013-6489,
    CVE-2013-6490)

  - The application does not protect against links to
    untrusted executable content. (CVE-2013-6486)"
  );
  script_set_attribute(attribute:"see_also", value:"http://hg.pidgin.im/pidgin/main/rev/5010e6877abc");
  script_set_attribute(attribute:"see_also", value:"http://www.pidgin.im/news/security/?id=69");
  script_set_attribute(attribute:"see_also", value:"http://www.pidgin.im/news/security/?id=70");
  script_set_attribute(attribute:"see_also", value:"http://www.pidgin.im/news/security/?id=71");
  script_set_attribute(attribute:"see_also", value:"http://www.pidgin.im/news/security/?id=72");
  script_set_attribute(attribute:"see_also", value:"http://www.pidgin.im/news/security/?id=73");
  script_set_attribute(attribute:"see_also", value:"http://www.pidgin.im/news/security/?id=74");
  script_set_attribute(attribute:"see_also", value:"http://www.pidgin.im/news/security/?id=75");
  script_set_attribute(attribute:"see_also", value:"http://www.pidgin.im/news/security/?id=76");
  script_set_attribute(attribute:"see_also", value:"http://www.pidgin.im/news/security/?id=77");
  script_set_attribute(attribute:"see_also", value:"http://www.pidgin.im/news/security/?id=78");
  script_set_attribute(attribute:"see_also", value:"http://www.pidgin.im/news/security/?id=79");
  script_set_attribute(attribute:"see_also", value:"http://www.pidgin.im/news/security/?id=80");
  script_set_attribute(attribute:"see_also", value:"http://www.pidgin.im/news/security/?id=81");
  script_set_attribute(attribute:"see_also", value:"http://www.pidgin.im/news/security/?id=82");
  script_set_attribute(attribute:"see_also", value:"http://www.pidgin.im/news/security/?id=83");
  script_set_attribute(attribute:"see_also", value:"http://www.pidgin.im/news/security/?id=84");
  script_set_attribute(attribute:"see_also", value:"http://www.pidgin.im/news/security/?id=85");
  script_set_attribute(attribute:"solution", value:"Upgrade to Pidgin 2.10.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pidgin:pidgin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("pidgin_installed.nasl");
  script_require_keys("SMB/Pidgin/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

path = get_kb_item_or_exit("SMB/Pidgin/Path");
version = get_kb_item_or_exit("SMB/Pidgin/Version");
fixed_version = '2.10.8';

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path               : ' + path +
      '\n  Installed version  : ' + version +
      '\n  Fixed version      : ' + fixed_version + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Pidgin", version, path);
