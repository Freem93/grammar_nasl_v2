#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(72212);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/09 15:44:47 $");

  script_cve_id("CVE-2013-7239", "CVE-2013-7290", "CVE-2013-7291");
  script_bugtraq_id(64559, 64988, 64989);
  script_osvdb_id(101565, 102515, 102587);

  script_name(english:"memcached < 1.4.17 Multiple Vulnerabilities");
  script_summary(english:"Checks version of memcached");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains a memory-based object store that is
potentially affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version, the version of memcached
installed on the remote host is a version prior to 1.4.17.  It is,
therefore, reportedly affected by the following vulnerabilities :

  - An error exists related to handling SASL requests
    that could allow authentication bypasses.
    (CVE-2013-7239)

  - An error exists in the function 'do_item_get' in the
    file 'items.c' that could cause buffer overreads and
    allow denial of service attacks. (CVE-2013-7290)

  - An error related to logging and verbose mode could
    allow some requests to cause denial of service
    conditions. (CVE-2013-7291)"
  );
  script_set_attribute(attribute:"see_also", value:"https://code.google.com/p/memcached/wiki/ReleaseNotes1417");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2013/q4/572");
  # https://github.com/memcached/memcached/commit/87c1cf0f20be20608d3becf854e9cf0910f4ad32
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d0080e1b");
  script_set_attribute(attribute:"see_also", value:"https://code.google.com/p/memcached/issues/detail?id=306");
  script_set_attribute(attribute:"solution", value:"Upgrade to memcached 1.4.17 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/30");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:memcached:memcached");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("memcached_detect.nasl");
  script_require_keys("Services/memcached");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:'memcached', exit_on_fail:TRUE);
ver  = get_kb_item_or_exit("memcache/version/"+port);

if (report_paranoia < 2) audit(AUDIT_PARANOID);
if (ver =~ "^1(\.4)?$") audit(AUDIT_VER_NOT_GRANULAR, "memcached", port, ver);

fix = "1.4.17";
if (ver_compare(ver:ver, fix:fix, strict:FALSE) < 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "memcached", port, ver);
