#TRUSTED 8a532f3806e1d8c873b27fe8b1d6e99b071a482f06b9c46a6acf85361ea9808449ce370b401590a8fc685269107fb46ee785fe30ae6026dd3319d27733e34c34660438ff2c71a2705dac2c2b1fc9ba5e5861251096da5a6e3123dd2cc69befff7ebfde743ad0d63076c39e7197a4561647063ce97ae64c70caf3e8881720e562ec2e53fc7acce5dfc55cf802805b47c7afc5ff61d16c5a20ccabbd3a3614085c778ba0f7255d6bd4bbcdab4cc7b0041773567210101c2164a869f801eeafc49288a6f554e3d4b413b6bcb086a7be9c3145ad6efa93491022a19ceea0affb28a2ae39ef94700dda0f57f3b779013bfc0bc4b48ce0630f708ad26b7287d7d43af71acf70a8eaf7c14a222b6dd6ef0a7b27d7903afad1c54329f6cb3bb65055dd3268ef23188df109d0c1ba62a6cfe28d27160b4487897aa680181eaeaca21ceeadeaa1da08b1638458a98cba654d7d559f7d3cd21f1c57eb6fae1166ba8e9f4bd73114295f29c85456a17a329eb7938a23844c16930d9e04268c973a9a7cf2b16f73f5ec7f74f67185e85aa4bc058af43223b11cdf59987d7062ad5af5eacf149a7e216890bff33fdf925ae3090f554e82a4c9f1c975ce944415336130193ec5e3d5c241b7446382075b03e7a7aa166b43e4e476b977b42fbc19a16851c38bcdb5eeafc957b995de291465fa90de3a2dec9898640512ee5def85bf237f2260382f
#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("script_get_preference_file_location")) exit(0);
if (!find_in_path("hydra")) exit(0, "Hydra was not found in '$PATH'.");

include("compat.inc");

if (description)
{
 script_id(15872);
 script_version("1.10");
 script_set_attribute(attribute:"plugin_modification_date", value:"2012/07/27");

 script_name(english:"Hydra: FTP");
 script_summary(english:"Brute force FTP authentication with Hydra");

 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine FTP passwords through brute force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find FTP accounts and passwords by brute
force. 

To use this plugin, enter the 'Logins file' and the 'Passwords file'
under the 'Hydra (NASL wrappers options)' advanced settings block.");
 script_set_attribute(attribute:"solution", value:"Change the passwords for the affected accounts.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/01");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2012 Tenable Network Security, Inc.");
 script_family(english:"Brute force attacks");

 script_dependencies("hydra_options.nasl", "ftpserver_detect_type_nd_version.nasl");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_ports("Services/ftp", 21);
 script_timeout(0);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

force = get_kb_item("/tmp/hydra/force_run");
if (! force) exit(0, "Neither 'thorough_tests' nor 'force_run' is set.");

logins = get_kb_item("Secret/hydra/logins_file");
if (isnull(logins)) exit(0, "No Hydra logins file.");

port = get_service(svc:"ftp", exit_on_fail:TRUE);       # port = 21?

# Check that the FTP server is still alive & answers quickly enough
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

r = recv_line(socket: soc, length: 1024);
close(soc);
if (r !~ '^2[0-9][0-9][ -]') exit(1, "The banner from the FTP server listening on port "+port+" indicates a problem.");

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

if (get_kb_item("/tmp/hydra/service/ftp")) svc = "ftp";
else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'ftp' service.");
else exit(1, "Failed to get the list of services that the installed version of Hydra supports.");

i = 0;
argv[i++] = "hydra";
argv[i++] = "-s"; argv[i++] = port;
argv[i++] = "-L"; argv[i++] = logins;
s = "";
if (empty) s = "n";
if (login_pass) s+= "s";
if (s)
{
  argv[i++] = "-e"; argv[i++] = s;
}
passwd = get_kb_item("Secret/hydra/passwords_file");
if (passwd)
{
 argv[i++] = "-P"; argv[i++] = passwd;
} else if (s)
 exit(0, "No Hydra passwords file.");

if (exit_asap) argv[i++] = "-f";
if (tr >= ENCAPS_SSLv2) argv[i++] = "-S";

if (timeout > 0)
{
  argv[i++] = "-w";
  argv[i++] = timeout;
}
if (tasks > 0)
{
  argv[i++] = "-t";
  argv[i++] = tasks;
}

argv[i++] = get_host_ip();
argv[i++] = svc;

set_kb_item(name:"Hydra/"+svc+"/"+port+"/cmd_line", value:join(argv));

errors = make_list();
report = "";
results = pread(cmd:"hydra", argv:argv, nice:5);
foreach line (split(results, keep:FALSE))
{
  v = eregmatch(string: line, pattern: 'host:.*login: *(.*) password: *(.*)$');
  if (! isnull(v))
  {
    l = chomp(v[1]);
    p = chomp(v[2]);
    report = strcat(report, 'username: ', l, '\tpassword:', p, '\n');
    set_kb_item(name: 'Hydra/ftp/'+port, value: l + '\t' + p);
  }
  else if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port:port, extra:'\nHydra discovered the following FTP credentials :\n\n' + report);

if (max_index(errors) > 0)
{
  msg = '';
  n = 0;
  foreach error (list_uniq(errors))
  {
    n++;
    if (n < 20) msg = strcat(msg, error, '\n');
  }

  set_kb_item(name:"Hydra/errors/"+svc+"/"+port, value:n);
  set_kb_item(name:"Hydra/error_msg/"+svc+"/"+port, value:msg);

  exit(1, "One or more errors occurred while running Hydra against the FTP server listening on port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the FTP server listening on port "+port+".");
