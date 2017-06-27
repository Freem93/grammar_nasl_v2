#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52533);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/03 21:08:35 $");
  script_cve_id(
    "CVE-2010-1585",
    "CVE-2011-0051",
    "CVE-2011-0053",
    "CVE-2011-0054",
    "CVE-2011-0055",
    "CVE-2011-0056",
    "CVE-2011-0057",
    "CVE-2011-0058",
    "CVE-2011-0059",
    "CVE-2011-0062"
  );
  script_bugtraq_id(
    46368,
    46643,
    46645,
    46648,
    46650,
    46652,
    46660,
    46661,
    46663
  );
  script_osvdb_id(
    64150,
    72437,
    72438,
    72439,
    72440,
    72441,
    72442,
    72443,
    72444,
    72445,
    72446,
    72447,
    72448,
    72449,
    72454,
    72456,
    72457,
    72458,
    72459,
    72460,
    72461,
    72465,
    72467
  );
  script_xref(name:"Secunia", value:"43550");

  script_name(english:"SeaMonkey < 2.0.12 Multiple Vulnerabilities");
  script_summary(english:"Checks version of SeaMonkey");

  script_set_attribute(attribute:"synopsis",value:
"The remote Windows host contains a web browser affected by multiple
vulnerabilities");
  script_set_attribute(attribute:"description",value:
"The installed version of SeaMonkey is earlier than 2.0.12.  Such
versions are potentially affected by multiple vulnerabilities :

  - Multiple memory corruption errors exist and may lead to
    arbitrary code execution. (MFSA 2011-01)

  - An error exists in the processing of recursive calls to
    'eval()' when the call is wrapped in a try/catch 
    statement. This error causes dialog boxes to be
    displayed with no content and non-functioning buttons.
    Closing the dialog results in default acceptance of the
    dialog. (MFSA 2011-02)
  
  - A use-after-free error exists in a method used by 
    'JSON.stringify' and can allow arbitrary code 
    execution. (MFSA 2011-03)

  - A buffer overflow vulnerability exists in the JavaScript
    engine's internal memory mapping of non-local 
    variables and may lead to code execution. (MFSA 2011-04)

  - A buffer overflow vulnerability exists in the JavaScript
    engine's internal mapping of string values and may lead 
    to code execution. (MFSA 2011-05)

  - A use-after-free error exists such that a JavaScript
    'Worker' can be used to keep a reference to an object
    which can be freed during garbage collection. This
    vulnerability may lead to arbitrary code execution.
    (MFSA 2011-06)

  - A buffer overflow error exists related to the creation
    very long strings and the insertion of those strings 
    into an HTML document. This vulnerability may lead to 
    arbitrary code execution. (MFSA 2011-07)

  - An input validation error exists in the class, 
    'ParanoidFragmentSink', which allows inline JavaScript
    and 'javascript:' URLs in a chrome document. Note that
    no unsafe usage occurs in Mozilla products, however
    community generated extensions could.(MFSA 2011-08)

  - A cross-site request forgery (CSRF) vulnerability
    exists when an HTTP 307 redirect is received in response
    to a plugin's request. The request is forwarded to the
    new location without the plugin's knowledge and with 
    custom headers intact, even across origins. 
    (MFSA 2011-10)");

  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2010/Apr/202");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-01.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-02.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-03.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-04.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-05.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-06.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-07.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-08.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-10.html");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9cab8da6");
  script_set_attribute(attribute:"solution", value:"Upgrade to SeaMonkey 2.0.12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/03");

  script_set_attribute(attribute:"plugin_type", value:"local");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:seamonkey");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("SeaMonkey/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/SeaMonkey/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "SeaMonkey");

mozilla_check_version(installs:installs, product:'seamonkey', fix:'2.0.12', severity:SECURITY_HOLE);
