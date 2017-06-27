#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(36215);
  script_version("$Revision: 1.16 $");

  script_cve_id(
    "CVE-2009-0652", 
    "CVE-2009-1302", 
    "CVE-2009-1303", 
    "CVE-2009-1304", 
    "CVE-2009-1305",
    "CVE-2009-1306", 
    "CVE-2009-1307", 
    "CVE-2009-1308", 
    "CVE-2009-1309", 
    "CVE-2009-1310",
    "CVE-2009-1311", 
    "CVE-2009-1312"
  );
  script_bugtraq_id(33837, 34656);
  script_osvdb_id(
    52659,
    53952,
    53953,
    53954,
    53955,
    53957,
    53958,
    53959,
    53960,
    53961,
    53962,
    53963,
    53964,
    53965,
    53966,
    53967,
    53968,
    53969,
    53970,
    53971,
    53972
  );

  script_name(english:"Firefox < 3.0.9 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The installed version of Firefox is earlier than 3.0.9. Such versions
are potentially affected by the following security issues :

  - Multiple remote memory corruption vulnerabilities exist
    that can be exploited to execute arbitrary code in the
    context of the user running the affected application.
    (MFSA 2009-14)

  - A flaw may exist where Unicode box drawing characters
    are allowed in Internationalized Domain Names where they
    could be visually confused with punctuation used in
    valid web addresses. An attacker can leverage this to
    launch a phishing-type scam against a victim. 
    (MFSA 2009-15)

  - A vulnerability exists when the 'jar:' scheme is used to
    wrap a URI which serves the content with
    'Content-Disposition: attachment'. An attacker can
    leverage this to subvert sites that use this mechanism
    to mitigate content injection attacks. (MFSA 2009-16)
  
  - When an Adobe Flash file is loaded via the
    'view-source:' scheme, the Flash plugin misinterprets
    the origin of the content as localhost. An attacker can
    leverage this to launch cross-site request forgery
    attacks. It is also possible to exploit this to place
    cookie-like objects on victim's computers.
    (MFSA 2009-17)

  - A vulnerability exists that allows attackers to inject
    arbitrary scripts into sites via XBL bindings. This
    vulnerability requires the attacker to have the ability
    to embed third-party stylesheets into the site. 
    (MFSA 2009-18)

  - Multiple remote code execution vulnerabilities exist
    caused by the creation of documents whose URI does not
    match the document's principle using XMLHttpRequest, as
    well as a flaw in the 'XPCNativeWrapper.ToString'
    '__proto__' coming from the wrong scope. (MFSA 2009-19)

  - A malicious MozSearch plugin could be created using a
    javascript: URI in the SearchForm value. An attacker can
    leverage this in order to inject code into arbitrary
    sites. (MFSA 2009-20)

  - An information disclosure vulnerability exists when
    saving the inner frame of a web page as a file when the
    outer page has POST data associated with it. 
    (MFSA 2009-21)

  - A cross-site scripting vulnerability exists when
    handling a Refresh header containing a javascript: URI.
    (MFSA 2009-22)" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-14.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-15.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-16.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-17.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-18.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-19.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-20.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-21.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-22.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 3.0.9 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_cwe_id(16, 20, 79, 200, 399);

 script_set_attribute(attribute:"plugin_publication_date", value: "2009/04/22");
 script_set_attribute(attribute:"patch_publication_date", value: "2009/04/21");
 script_cvs_date("$Date: 2016/11/28 21:52:56 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");
  exit(0);
}


include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport"); 

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'3.0.9', severity:SECURITY_HOLE);