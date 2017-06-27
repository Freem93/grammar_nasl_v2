#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86066);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/07/18 15:54:01 $");

  script_cve_id(
    "CVE-2013-5704",
    "CVE-2014-0067",
    "CVE-2014-3581",
    "CVE-2014-3583",
    "CVE-2014-8109",
    "CVE-2014-8161",
    "CVE-2014-8500",
    "CVE-2015-0228",
    "CVE-2015-0241",
    "CVE-2015-0242",
    "CVE-2015-0243",
    "CVE-2015-0244",
    "CVE-2015-0253",
    "CVE-2015-1349",
    "CVE-2015-3165",
    "CVE-2015-3166",
    "CVE-2015-3167",
    "CVE-2015-3183",
    "CVE-2015-3185",
    "CVE-2015-5911"
  );
  script_bugtraq_id(
    65721,
    66550,
    71590,
    71656,
    71657,
    72538,
    72540,
    72542,
    72543,
    72673,
    73040,
    73041,
    74787,
    74789,
    74790,
    75963,
    75964,
    75965
  );
  script_osvdb_id(
    103550,
    105190,
    112168,
    114570,
    115375,
    115524,
    118033,
    118035,
    118036,
    118037,
    118038,
    118546,
    119066,
    119904,
    122456,
    122457,
    122458,
    123122,
    123123,
    127700
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2015-09-16-4");

  script_name(english:"Mac OS X : OS X Server < 5.0.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the OS X Server version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update for OS X Server.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has a version of OS X Server installed that
is prior to 5.0.3. It is, therefore, affected by the following
vulnerabilities :

  - A flaw exists in the mod_headers module that allows HTTP
    trailers to replace HTTP headers late during request
    processing. A remote attacker can exploit this to inject
    arbitrary headers. This can also cause some modules to
    function incorrectly or appear to function incorrectly.
    (CVE-2013-5704)

  - A privilege escalation vulnerability exists due to the
    'make check' command not properly invoking initdb to
    specify authentication requirements for a database
    cluster to be used for tests. A local attacker can
    exploit this issue to gain temporary server access and
    elevated privileges. (CVE-2014-0067)

  - A NULL pointer dereference flaw exists in module
    mod_cache. A remote attacker, using an empty HTTP
    Content-Type header, can exploit this vulnerability to
    crash a caching forward proxy configuration, resulting
    in a denial of service if using a threaded MPM.
    (CVE-2014-3581)

  - A out-of-bounds memory read flaw exists in module
    mod_proxy_fcgi. An attacker, using a remote FastCGI
    server to send long response headers, can exploit this
    vulnerability to cause a denial of service by causing
    a buffer over-read. (CVE-2014-3583)

  - A flaw exists in module mod_lua when handling a
    LuaAuthzProvider used in multiple Require directives
    with different arguments. An attacker can exploit this
    vulnerability to bypass intended access restrictions.
    (CVE-2014-8109)

  - An information disclosure vulnerability exists due to
    improper handling of restricted column values in
    constraint-violation error messages. An authenticated,
    remote attacker can exploit this to gain access to
    sensitive information. (CVE-2014-8161)

  - A flaw exists within the Domain Name Service due to an
    error in the code used to follow delegations. A remote
    attacker, with a maliciously-constructed zone or query,
    can cause the service to issue unlimited queries,
    resulting in resource exhaustion. (CVE-2014-8500)

  - A flaw exists in the lua_websocket_read() function in
    the 'mod_lua' module due to incorrect handling of
    WebSocket PING frames. A remote attacker can exploit
    this, by sending a crafted WebSocket PING frame after a
    Lua script has called the wsupgrade() function, to crash
    a child process, resulting in a denial of service
    condition. (CVE-2015-0228)

  - Multiple vulnerabilities exist due to several buffer
    overflow errors related to the 'to_char' functions. An
    authenticated, remote attacker can exploit these issues
    to cause a denial of service or arbitrary code
    execution. (CVE-2015-0241)

  - Multiple vulnerabilities exist due to several
    stack-based buffer overflow errors in various *printf()
    functions. The overflows are due to improper validation
    of user-supplied input when formatting a floating point
    number where the requested precision is greater than
    approximately 500. An authenticated, remote attacker
    can exploit these issues to cause a denial of service or
    arbitrary code execution. (CVE-2015-0242)

  - Multiple vulnerabilities exist due to an overflow
    condition in multiple functions in the 'pgcrypto'
    extension. The overflows are due to improper validation
    of user-supplied input when tracking memory sizes. An
    authenticated, remote attacker can exploit these issues
    to cause a denial of service or arbitrary code
    execution. (CVE-2015-0243)

  - A SQL injection vulnerability exists due to improper
    sanitization of user-supplied input when handling
    crafted binary data within a command parameter. An
    authenticated, remote attacker can exploit this issue
    to inject or manipulate SQL queries, allowing the
    manipulation or disclosure of arbitrary data.
    (CVE-2015-0244)

  - A NULL pointer dereference flaw exists in the
    read_request_line() function due to a failure to
    initialize the protocol structure member. A remote 
    attacker can exploit this flaw, on installations that
    enable the INCLUDES filter and has an ErrorDocument 400
    directive specifying a local URI, by sending a request
    that lacks a method, to cause a denial of service
    condition. (CVE-2015-0253)

  - A denial of service vulnerability exists due to an error
    relating to DNSSEC validation and the managed-keys
    feature. A remote attacker can trigger an incorrect
    trust-anchor management scenario in which no key is
    ready for use, resulting in an assertion failure and
    daemon crash. (CVE-2015-1349)

  - A flaw exists in PostgreSQL client disconnect timeout 
    expiration that is triggered when a timeout interrupt 
    is fired partway through the session shutdown sequence. 
    (CVE-2015-3165)

  - A flaw exists in the printf() functions due to a failure
    to check for errors. A remote attacker can use this to
    gain access to sensitive information. (CVE-2015-3166)

  - The pgcrypto component in PostgreSQL has multiple error
    messages for decryption with an incorrect key. A remote
    attacker can use this to recover keys from other
    systems. (CVE-2015-3167)

  - A flaw exists in the chunked transfer coding
    implementation due to a failure to properly parse chunk
    headers. A remote attacker can exploit this to conduct
    HTTP request smuggling attacks. (CVE-2015-3183)

  - A flaw exists in the ap_some_auth_required() function
    due to a failure to consider that a Require directive
    may be associated with an authorization setting rather
    than an authentication setting. A remote attacker can
    exploit this, if a module that relies on the 2.2 API
    behavior exists, to bypass intended access restrictions.
    (CVE-2015-3185)

  - Multiple unspecified XML flaws exist in the Wiki Server
    based on Twisted. (CVE-2015-5911)");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT205219");
  # http://prod.lists.apple.com/archives/security-announce/2015/Sep/msg00004.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b32f8315");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mac OS X Server version 5.0.3 or later.

Note that OS X Server 5.0.3 is available only for OS X 10.10.5 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_server_services.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Server/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

version = get_kb_item_or_exit("MacOSX/Server/Version");

fixed_version = "5.0.3";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  set_kb_item(name:'www/0/SQLInjection', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + 
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "OS X Server", version);
