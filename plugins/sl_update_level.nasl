#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61373);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/01/04 15:27:48 $");

  script_name(english:"Scientific Linux Update Level");
  script_summary(english:"Checks Scientific Linux release info");

  script_set_attribute(attribute:"synopsis", value:"The remote Scientific Linux host is out-of-date.");
  script_set_attribute(attribute:"description", value:
"The remote Scientific Linux host is missing the latest update level.
Since updating Scientific Linux brings a host up to the most recent
Update Level, this means that it has not been updated recently and
likely to be affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://www.scientificlinux.org/distributions/roadmap");
  script_set_attribute(attribute:"solution", value:"Apply the latest Update Level.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");


# nb: https://www.scientificlinux.org/distributions/roadmap shows no versions before SL 3.x.
lastupdate = make_array();
lastupdate["3.0"] = 0;
lastupdate["4"]   = 9;
lastupdate["5"]   = 11;
lastupdate["6"]   = 7;
lastupdate["7"]   = 1;


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");

match = eregmatch(string:release, pattern: "release ([0-9]+(\.[0-9]+)?)\.([0-9]+)");
if (isnull(match)) exit(1, "Failed to identify the update level from the Scientific Linux release info.");

release = match[1];
update_level = int(match[3]);
if (isnull(lastupdate[release])) exit(1, "Unknown update level for release '"+release+"'.");

if (update_level < lastupdate[release])
{
  report =
    '\n  Installed release : ' + release + '.' + update_level +
    '\n  Latest release    : ' + release + '.' + lastupdate[release];
  security_hole(port:0, extra:report);
  exit(0);
}
else exit(0, "The host is running Scientific Linux "+release+"."+update_level+", which is the latest Update Level for release "+release+".x.");
