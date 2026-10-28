package Test::Nginx;

# Stand-in for nginx-tests' Test::Nginx, preloaded by the differential
# harness (`perl -I… -MTest::Nginx file.t`): a test file then writes its
# configuration and files into $DIFFTEST_DIR and records the requests it
# would send (port, hex bytes, per line in requests.tsv) instead of running
# anything. Ports stay as written; the harness maps them.

use warnings;
use strict;

use base qw/ Exporter /;

our @EXPORT = qw/ log_in log_out http http_get http_head port /;
our @EXPORT_OK = qw/
	http_gzip_request http_gzip_like http_start http_end http_content
/;
our %EXPORT_TAGS = (
	gzip => [ qw/ http_gzip_request http_gzip_like / ]
);

my $DIR = $ENV{DIFFTEST_DIR} or die "DIFFTEST_DIR not set\n";

sub new { my $self = { _testdir => $DIR }; return bless $self; }

sub _record {
	my ($port, $data) = @_;
	open my $f, '>>', "$DIR/requests.tsv" or die;
	binmode $f;
	print $f $port, "\t", unpack('H*', $data), "\n";
	close $f;
}

sub has { return $_[0]; }
sub has_module { return 1; }
sub has_feature { return 1; }
sub has_version { return 1; }
sub has_daemon { return $_[0]; }
sub plan { return $_[0]; }
sub todo_alerts { return $_[0]; }
sub run { return $_[0]; }
sub try_run { return $_[0]; }
sub args { return $_[0]; }
sub reload { return 1; }
sub stop { return $_[0]; }
sub stop_daemons { return $_[0]; }
sub run_daemon { return $_[0]; }
sub waitforfile { return 1; }
sub waitforsocket { return 1; }
sub dump_config { return ''; }
sub testdir { return $DIR; }
sub port { return $_[0]; }
sub log_in { }
sub log_out { }

sub read_file {
	my ($self, $name) = @_;
	open my $f, '<', "$DIR/$name" or return '';
	local $/;
	my $c = <$f>;
	close $f;
	return $c;
}

sub write_file {
	my ($self, $name, $content) = @_;
	open my $f, '>', "$DIR/$name" or die "Can't create $name: $!";
	binmode $f;
	print $f $content;
	close $f;
	return $self;
}

sub write_file_expand {
	my ($self, $name, $content) = @_;
	$content =~ s/%%TEST_GLOBALS%%//gms;
	$content =~ s/%%TEST_GLOBALS_HTTP%%/root $DIR;\n/gms;
	$content =~ s/%%TEST_GLOBALS_STREAM%%//gms;
	$content =~ s/%%TESTDIR%%/$DIR/gms;
	$content =~ s/%%PORT_(\d+)%%/$1/gms;
	$content =~ s/%%PORT_(\d+)_UDP%%/$1/gms;
	return $self->write_file($name, $content);
}

sub http_get {
	my ($url, %extra) = @_;
	return http("GET $url HTTP/1.0\nHost: localhost\n\n", %extra);
}

sub http_head {
	my ($url, %extra) = @_;
	return http("HEAD $url HTTP/1.0\nHost: localhost\n\n", %extra);
}

sub http_gzip_request {
	my ($url) = @_;
	return http("GET $url HTTP/1.1\nHost: localhost\nConnection: close\n"
		. "Accept-Encoding: gzip\n\n");
}

sub http {
	my ($request, %extra) = @_;
	return '' if $extra{socket} or $extra{start} or $extra{aborted};
	my $port = $extra{SSL} ? 8443 : 8080;
	$port = $1 if ($extra{PeerAddr} || '') =~ /:(\d+)$/;
	$port = "ssl:$port" if $extra{SSL};
	_record($port, $request . ($extra{body} // ''));
	return '';
}

sub http_start { http(@_); return undef; }
sub http_end { return ''; }
sub http_content { return ''; }
sub http_gzip_like { return; }

1;
