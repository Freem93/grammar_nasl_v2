#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64458);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/11 20:08:42 $");

  script_cve_id("CVE-2012-5621");
  script_bugtraq_id(56790);
  script_osvdb_id(88292);

  script_name(english:"Ekiga < 4.0.0 Invalid UTF-8 Character Connection Data Parsing DoS");
  script_summary(english:"Checks version in SIP banner");

  script_set_attribute(attribute:"synopsis", value:
"The version of Ekiga installed on the remote host may be affected by a
denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to the version in its SIP banner, the version of Ekiga
running on the remote host is potentially affected by a vulnerability
that could allow a remote, unauthenticated attacker to cause a denial of
service via invalid UTF-8 characters in the remote user's connection
data.");
  script_set_attribute(attribute:"solution", value:"Upgrade to Ekiga 4.0.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"see_also", value:"http://git.gnome.org/browse/ekiga/tree/NEWS?id=EKIGA_4_0_0");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.gnome.org/show_bug.cgi?id=653009");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ekiga:ekiga");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("ekiga_detection.nasl");
  script_require_keys("ekiga/sip_detected", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("ekiga/sip_detected");

# see if we were able to get version info from the Ekiga SIP services
ekiga_kbs = get_kb_list("sip/ekiga/*/version");
if (isnull(ekiga_kbs)) exit(0, "Could not obtain any version information from the Ekiga SIP instance(s).");

# Prevent potential false positives.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

is_vuln = FALSE;
not_vuln_installs = make_list();
errors = make_list();
fixed = "4.0.0";

foreach kb_name (keys(ekiga_kbs))
{
  matches = eregmatch(pattern:"/(udp|tcp)/([0-9]+)/version", string:kb_name);  
  if (isnull(matches))
  {
    errors = make_list(errors, "Unexpected error parsing port number from kb name: "+kb_name);
    continue;
  }

  proto = matches[1];
  port  = matches[2];
  version = ekiga_kbs[kb_name];

  banner = get_kb_item("sip/ekiga/" + proto + "/" + port + "/source"); 
  if (!banner)
  {
    # We have version but banner is missing; log error
    # and use in version-check though.
    errors = make_list(errors, "KB item 'sip/ekiga/" + proto + "/" + port + "/source' is missing");
    banner = 'unknown';
  }

  # Affected < 4.0.0
  if (version =~ "^[0-3]\.")
  {
    is_vuln = TRUE;
    if (report_verbosity > 0)
    {
      report = 
        '\n  Version source    : ' + banner +
        '\n  Installed version : ' + version + 
        '\n  Fixed version     : ' + fixed + '\n';
      security_warning(port:port, proto:proto, extra:report);
    }
    else security_warning(port:port, proto:proto);
  }
  else not_vuln_installs = make_list(not_vuln_installs, version + " on port " + proto + "/" + port);
}

if (is_vuln)
{
  if (max_index(errors)) exit(1, "The results may be incomplete because of one or more errors verifying installs.");
  else  exit(0);
}
else
{
  if (max_index(errors))
  {
    if (max_index(errors) == 1) errmsg = errors[0];
    else errmsg = 'Errors were encountered verifying installs : \n  ' + join(errors, sep:'\n  ');
  
    exit(1, errmsg);
  }

  installs = max_index(not_vuln_installs);
  if (installs == 0) audit(AUDIT_NOT_INST, "Ekiga");
  else if (installs == 1) audit(AUDIT_INST_VER_NOT_VULN, "Ekiga " + not_vuln_installs[0]);
  else exit(0, "The Ekiga installs (" + join(not_vuln_installs, sep:", ") + ") are not affected.");
}
