#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40827);
  script_version("$Revision: 1.9 $");

  script_cve_id(
    "CVE-2009-3044",
    "CVE-2009-3045",
    "CVE-2009-3046",
    "CVE-2009-3047",
    "CVE-2009-3049"
  );
  script_bugtraq_id(36202);
  script_osvdb_id(57639, 57640, 57641, 57642, 57790);
  script_xref(name:"Secunia", value:"36414");
  
  script_name(english:"Opera < 10.0 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Opera");

  script_set_attribute(attribute:"synopsis",value:
"The remote host contains a web browser that is affected by multiple
issues."
  );
  script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host is earlier than
10.0 and thus reportedly affected by multiple issues :

  - Opera does not check the revocation status for
    intermediate certificates not served by the server. If
    the intermediate is revoked, this might not impact the
    security rating in Opera, and the site might be shown as
    secure. (929)

  - The collapsed Address bar can in some cases temporarily
    show the previous domain of the present site. (930)

  - Some Unicode characters are treated incorrectly which
    might cause international domain names that use them to
    be shown in the wrong format. Showing these addresses in
    Unicode instead of punycode could allow for limited
    address spoofing. (932)

  - The application trusts root X.509 certificates signed 
    with the MD2 algorithm. (933)

  - Certificates which use a wild card immediately before
    the top level domain, or nulls in the domain name, may
    pass validation checks in Opera. Sites using such
    certificates may then incorrectly be presented as
    secure. (934)"
  );

  script_set_attribute(attribute:"see_also",
    value:"http://www.opera.com/support/kb/view/929/"
  );
  script_set_attribute(attribute:"see_also",
    value:"http://www.opera.com/support/kb/view/930/"
  );
  script_set_attribute(attribute:"see_also",
    value:"http://www.opera.com/support/kb/view/932/"
  );
  script_set_attribute(attribute:"see_also",
    value:"http://www.opera.com/support/kb/view/933/"
  );
  script_set_attribute(attribute:"see_also",
    value:"http://www.opera.com/support/kb/view/934/"
  );
  script_set_attribute(attribute:"solution", 
    value:"Upgrade to Opera 10.0 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264, 310);
  script_set_attribute(attribute:"vuln_publication_date",
    value:"2009/09/01"
  );
  script_set_attribute(attribute:"patch_publication_date",
    value:"2009/09/01"
  );
  script_set_attribute(attribute:"plugin_publication_date",
    value:"2009/09/01"
  );
 script_cvs_date("$Date: 2016/12/07 20:46:55 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("opera_installed.nasl");
  script_require_keys("SMB/Opera/Version");

  exit(0);
}

include("global_settings.inc");

version_ui = get_kb_item("SMB/Opera/Version_UI");
version = get_kb_item("SMB/Opera/Version");
if (isnull(version)) exit(1, "Opera version info was not found in the registry.");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] < 10)
{
  if (report_verbosity > 0 && version_ui)
  {
    report = string(
      "\n",
      "Opera ", version_ui, " is currently installed on the remote host.\n"
    );
    security_warning(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_warning(port:get_kb_item("SMB/transport"));
}
exit(0, "The installed version of Opera is not affected");
