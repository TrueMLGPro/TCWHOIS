package thecollectiveweb.com.tcwhois;

import android.util.Log;

import org.apache.commons.net.whois.WhoisClient;

import java.io.IOException;
import java.net.SocketException;
import java.text.SimpleDateFormat;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class TCWHOIS {
    private static final String TAG = "TCWHOIS";

    private String domainName;

    public interface WhoisCallback {
        void onResult(String data);
        void onError(Exception e);
    }

    private static final ExecutorService EXECUTOR = Executors.newCachedThreadPool();

    // regex whois parser
    private static final String WHOIS_SERVER_PATTERN = "Whois Server:\\s(.*)";

    private static final Pattern whoisServerPattern = Pattern.compile(WHOIS_SERVER_PATTERN);

    private static final Map<String, String> WHOIS_SERVERS = createWhoisServers();

    private static Map<String, String> createWhoisServers() {
        Map<String, String> servers = new LinkedHashMap<>();
        servers.put("com", WhoisClient.DEFAULT_HOST);
        servers.put("in", "whois.inregistry.net");
        servers.put("ac", "whois.nic.ac");
        servers.put("ad", "whois.ripe.net");
        servers.put("ae", "whois.aeda.net.ae");
        servers.put("aero", "whois.aero");
        servers.put("af", "whois.nic.af");
        servers.put("ag", "whois.nic.ag");
        servers.put("ai", "whois.nic.ai");
        servers.put("al", "whois.ripe.net");
        servers.put("am", "whois.amnic.net");
        servers.put("as", "whois.nic.as");
        servers.put("asia", "whois.nic.asia");
        servers.put("at", "whois.nic.at");
        servers.put("au", "whois.aunic.net");
        servers.put("aw", "whois.nic.aw");
        servers.put("ax", "whois.ax");
        servers.put("az", "whois.ripe.net");
        servers.put("ba", "whois.ripe.net");
        servers.put("bar", "whois.nic.bar");
        servers.put("be", "whois.dns.be");
        servers.put("berlin", "whois.nic.berlin");
        servers.put("best", "whois.nic.best");
        servers.put("bg", "whois.register.bg");
        servers.put("bi", "whois.nic.bi");
        servers.put("biz", "whois.neulevel.biz");
        servers.put("bj", "whois.nic.bj");
        servers.put("bo", "whois.nic.bo");
        servers.put("br", "whois.nic.br");
        servers.put("br.com", "whois.centralnic.com");
        servers.put("bt", "whois.netnames.net");
        servers.put("bw", "whois.nic.net.bw");
        servers.put("by", "whois.cctld.by");
        servers.put("bz", "whois.belizenic.bz");
        servers.put("bzh", "whois-bzh.nic.fr");
        servers.put("ca", "whois.cira.ca");
        servers.put("cat", "whois.cat");
        servers.put("cc", "whois.nic.cc");
        servers.put("cd", "whois.nic.cd");
        servers.put("ceo", "whois.nic.ceo");
        servers.put("cf", "whois.dot.cf");
        servers.put("ch", "whois.nic.ch");
        servers.put("ci", "whois.nic.ci");
        servers.put("ck", "whois.nic.ck");
        servers.put("cl", "whois.nic.cl");
        servers.put("cloud", "whois.nic.cloud");
        servers.put("club", "whois.nic.club");
        servers.put("cn", "whois.cnnic.net.cn");
        servers.put("cn.com", "whois.centralnic.com");
        servers.put("co", "whois.nic.co");
        servers.put("co.nl", "whois.co.nl");
        servers.put("coop", "whois.nic.coop");
        servers.put("cx", "whois.nic.cx");
        servers.put("cy", "whois.ripe.net");
        servers.put("cz", "whois.nic.cz");
        servers.put("de", "whois.denic.de");
        servers.put("dk", "whois.dk-hostmaster.dk");
        servers.put("dm", "whois.nic.cx");
        servers.put("dz", "whois.nic.dz");
        servers.put("ec", "whois.nic.ec");
        servers.put("edu", "whois.educause.net");
        servers.put("ee", "whois.tld.ee");
        servers.put("eg", "whois.ripe.net");
        servers.put("es", "whois.nic.es");
        servers.put("eu", "whois.nic.bo");
        servers.put("eu.com", "whois.centralnic.com");
        servers.put("eus", "whois.nic.eus");
        servers.put("fi", "whois.fi");
        servers.put("fo", "whois.nic.fo");
        servers.put("fr", "whois.nic.fr");
        servers.put("gb", "whois.ripe.net");
        servers.put("gb.com", "whois.centralnic.com");
        servers.put("gb.net", "whois.centralnic.com");
        servers.put("qc.com", "whois.centralnic.com");
        servers.put("ge", "whois.ripe.net");
        servers.put("gg", "whois.gg");
        servers.put("gi", "whois2.afilias-grs.net");
        servers.put("gl", "whois.nic.gl");
        servers.put("gm", "whois.ripe.net");
        servers.put("gov", "whois.nic.gov");
        servers.put("gr", "whois.ripe.net");
        servers.put("gs", "whois.nic.gs");
        servers.put("gy", "whois.registry.gy");
        servers.put("hamburg", "whois.nic.hamburg");
        servers.put("hiphop", "whois.uniregistry.net");
        servers.put("hk", "whois.hknic.net.hk");
        servers.put("hm", "whois.registry.hm");
        servers.put("hn", "whois2.afilias-grs.net");
        servers.put("host", "whois.nic.host");
        servers.put("hr", "whois.dns.hr");
        servers.put("ht", "whois.nic.ht");
        servers.put("hu", "whois.nic.hu");
        servers.put("hu.com", "whois.centralnic.com");
        servers.put("id", "whois.pandi.or.id");
        servers.put("ie", "whois.domainregistry.ie");
        servers.put("il", "whois.isoc.org.il");
        servers.put("im", "whois.nic.im");
        servers.put("info", "whois.afilias.info");
        servers.put("ing", "domain-registry-whois.l.google.com");
        servers.put("ink", "whois.centralnic.com");
        servers.put("int", "whois.isi.edu");
        servers.put("io", "whois.nic.io");
        servers.put("iq", "whois.cmc.iq");
        servers.put("ir", "whois.nic.ir");
        servers.put("is", "whois.isnic.is");
        servers.put("it", "whois.nic.it");
        servers.put("je", "whois.je");
        servers.put("jobs", "obswhois.verisign-grs.com");
        servers.put("jp", "whois.jprs.jp");
        servers.put("ke", "whois.kenic.or.ke");
        servers.put("kg", "whois.domain.kg");
        servers.put("ki", "whois.nic.ki");
        servers.put("kr", "whois.kr");
        servers.put("kz", "whois.nic.kz");
        servers.put("la", "whois2.afilias-grs.net");
        servers.put("li", "whois.nic.li");
        servers.put("london", "whois.nic.london");
        servers.put("lt", "whois.domreg.lt");
        servers.put("lu", "whois.restena.lu");
        servers.put("lv", "whois.nic.lv");
        servers.put("ly", "whois.lydomains.com");
        servers.put("ma", "whois.iam.net.ma");
        servers.put("mc", "whois.ripe.net");
        servers.put("md", "whois.nic.md");
        servers.put("me", "whois.nic.me");
        servers.put("mg", "whois.nic.mg");
        servers.put("mil", "whois.nic.mil");
        servers.put("mk", "whois.ripe.net");
        servers.put("ml", "whois.dot.ml");
        servers.put("mo", "whois.monic.mo");
        servers.put("mobi", "whois.dotmobiregistry.net");
        servers.put("ms", "whois.nic.ms");
        servers.put("mt", "whois.ripe.net");
        servers.put("mu", "whois.nic.mu");
        servers.put("museum", "whois.museum");
        servers.put("mx", "whois.nic.mx");
        servers.put("my", "whois.mynic.net.my");
        servers.put("mz", "whois.nic.mz");
        servers.put("na", "whois.na-nic.com.na");
        servers.put("name", "whois.nic.name");
        servers.put("nc", "whois.nc");
        servers.put("net", "whois.verisign-grs.com");
        servers.put("nf", "whois.nic.nf");
        servers.put("ng", "whois.nic.net.ng");
        servers.put("nl", "whois.domain-registry.nl");
        servers.put("no", "whois.norid.no");
        servers.put("no.com", "whois.centralnic.com");
        servers.put("nu", "whois.nic.nu");
        servers.put("nz", "whois.srs.net.nz");
        servers.put("om", "whois.registry.om");
        servers.put("ong", "whois.publicinterestregistry.net");
        servers.put("ooo", "whois.nic.ooo");
        servers.put("org", "whois.pir.org");
        servers.put("paris", "whois-paris.nic.fr");
        servers.put("pe", "kero.yachay.pe");
        servers.put("pf", "whois.registry.pf");
        servers.put("pics", "whois.uniregistry.net");
        servers.put("pl", "whois.dns.pl");
        servers.put("pm", "whois.nic.pm");
        servers.put("pr", "whois.nic.pr");
        servers.put("press", "whois.nic.press");
        servers.put("pro", "whois.registrypro.pro");
        servers.put("pt", "whois.dns.pt");
        servers.put("pub", "whois.unitedtld.com");
        servers.put("pw", "whois.nic.pw");
        servers.put("qa", "whois.registry.qa");
        servers.put("re", "whois.nic.re");
        servers.put("ro", "whois.rotld.ro");
        servers.put("rs", "whois.rnids.rs");
        servers.put("ru", "whois.tcinet.ru");
        servers.put("sa", "saudinic.net.sa");
        servers.put("sa.com", "whois.centralnic.com");
        servers.put("sb", "whois.nic.net.sb");
        servers.put("sc", "whois2.afilias-grs.net");
        servers.put("se", "whois.nic-se.se");
        servers.put("se.com", "whois.centralnic.com");
        servers.put("se.net", "whois.centralnic.com");
        servers.put("sg", "whois.nic.net.sg");
        servers.put("sh", "whois.nic.sh");
        servers.put("si", "whois.arnes.si");
        servers.put("sk", "whois.sk-nic.sk");
        servers.put("sm", "whois.nic.sm");
        servers.put("st", "whois.nic.st");
        servers.put("so", "whois.nic.so");
        servers.put("su", "whois.tcinet.ru");
        servers.put("sx", "whois.sx");
        servers.put("sy", "whois.tld.sy");
        servers.put("tc", "whois.adamsnames.tc");
        servers.put("tel", "whois.nic.tel");
        servers.put("tf", "whois.nic.tf");
        servers.put("th", "whois.thnic.net");
        servers.put("tj", "whois.nic.tj");
        servers.put("tk", "whois.nic.tk");
        servers.put("tl", "whois.domains.tl");
        servers.put("tm", "whois.nic.tm");
        servers.put("tn", "whois.ati.tn");
        servers.put("to", "whois.tonic.to");
        servers.put("top", "whois.nic.top");
        servers.put("tp", "whois.domains.tl");
        servers.put("tr", "whois.nic.tr");
        servers.put("travel", "whois.nic.travel");
        servers.put("tw", "whois.twnic.net.tw");
        servers.put("tv", "whois.nic.tv");
        servers.put("tz", "whois.tznic.or.tz");
        servers.put("ua", "whois.ua");
        servers.put("ug", "whois.co.ug");
        servers.put("uk", "whois.nic.uk");
        servers.put("uk.com", "whois.centralnic.com");
        servers.put("uk.net", "whois.centralnic.com");
        servers.put("ac.uk", "whois.ja.net");
        servers.put("gov.uk", "whois.ja.net");
        servers.put("us", "whois.nic.us");
        servers.put("us.com", "whois.centralnic.com");
        servers.put("uy", "nic.uy");
        servers.put("uy.com", "whois.centralnic.com");
        servers.put("uz", "whois.cctld.uz");
        servers.put("va", "whois.ripe.net");
        servers.put("vc", "whois2.afilias-grs.net");
        servers.put("ve", "whois.nic.ve");
        servers.put("vg", "ccwhois.ksregistry.net");
        servers.put("vu", "vunic.vu");
        servers.put("wang", "whois.nic.wang");
        servers.put("wf", "whois.nic.wf");
        servers.put("wiki", "whois.nic.wiki");
        servers.put("ws", "whois.website.ws");
        servers.put("xxx", "whois.nic.xxx");
        servers.put("xyz", "whois.nic.xyz");
        servers.put("yu", "whois.ripe.net");
        servers.put("za.com", "whois.centralnic.com");
        return servers;
    }

    private static final Set<String> EQUALS_QUERY_TLDS = Collections.singleton("com");

    public void setDomain(String domain) {
        this.domainName = domain;
    }

    public static void getWhoisAsync(String domain, WhoisCallback callback) {
        getWhoisAsync(domain, null, callback);
    }

    public static void getWhoisAsync(String domain, String tld, WhoisCallback callback) {
        final TCWHOIS client = new TCWHOIS();
        EXECUTOR.submit(() -> {
            try {
                String result = (tld == null)
                        ? client.getWhois(domain)
                        : client.getWhois(domain, tld);
                callback.onResult(result);
            } catch (Exception e) {
                callback.onError(e);
            }
        });
    }

    public static void shutdown() {
        EXECUTOR.shutdown();
    }

    public String getWhois(String domainName) {
        StringBuilder result = new StringBuilder("");

        WhoisClient whois = new WhoisClient();
        try {
            whois.connect(WhoisClient.DEFAULT_HOST);
            // whois.connect("whois.iana.org");

            // whois = google.com
            String primaryResponse = whois.query("=" + domainName);
            Log.v(TAG, primaryResponse);

            // append first result
            result.append(primaryResponse);
            whois.disconnect();

            appendReferralData(domainName, primaryResponse, result);
        } catch (SocketException e) {
            Log.e(TAG, "Whois lookup failed", e);
        } catch (IOException e) {
            Log.e(TAG, "Whois lookup failed", e);
        }

        return result.toString();
    }

    public String getWhois(String domainName, String tld) {
        StringBuilder result = new StringBuilder("");
        WhoisClient whois = new WhoisClient();
        try {
            String normalizedTld = (tld == null) ? null : tld.toLowerCase(Locale.US);
            String host = (normalizedTld == null) ? null : WHOIS_SERVERS.get(normalizedTld);
            String primaryResponse;
            if (host == null) {
                whois.connect(WhoisClient.DEFAULT_HOST);
                primaryResponse = whois.query("=" + domainName);
            } else {
                whois.connect(host);
                primaryResponse = EQUALS_QUERY_TLDS.contains(normalizedTld)
                        ? whois.query("=" + domainName)
                        : whois.query(domainName);
            }
            result.append(primaryResponse);
            whois.disconnect();

            appendReferralData(domainName, primaryResponse, result);
        } catch (SocketException e) {
            Log.e(TAG, "Whois lookup failed", e);
        } catch (IOException e) {
            Log.e(TAG, "Whois lookup failed", e);
        }

        return result.toString();
    }

    private void appendReferralData(String domainName, String firstResponse, StringBuilder result) {
        String whoisServerUrl = getWhoisServer(firstResponse);
        if (!whoisServerUrl.equals("")) {
            result.append(queryWithWhoisServer(domainName, whoisServerUrl));
        }
    }

    private String queryWithWhoisServer(String domainName, String whoisServer) {
        String result = "";
        WhoisClient whois = new WhoisClient();
        try {
            whois.connect(whoisServer);
            result = whois.query(domainName);
            whois.disconnect();
        } catch (SocketException e) {
            Log.e(TAG, "Referral query failed for " + whoisServer, e);
        } catch (IOException e) {
            Log.e(TAG, "Referral query failed for " + whoisServer, e);
        }

        return result;
    }

    private String getWhoisServer(String whoisResponse) {
        String result = "";

        Matcher matcher = whoisServerPattern.matcher(whoisResponse);

        // get last whois server
        while (matcher.find()) {
            result = matcher.group(1);
        }
        return result;
    }

    private static String extractWhoisField(String whois, int lineIndex) {
        String[] rawLines = whois.split("\n");
        if (lineIndex < 0 || lineIndex >= rawLines.length) {
            return null;
        }
        String[] parts = rawLines[lineIndex].split(": ", 2);
        if (parts.length < 2 || parts[1].isEmpty()) {
            return null;
        }
        return parts[1];
    }

    private static SimpleDateFormat createWhoisDateFormat() {
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US);
        dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
        return dateFormat;
    }

    public String getRegistryDomainId(String domain) {
        this.domainName = domain;
        String whois = getWhois(domainName, "com");
        if (!whois.contains("No match for")) {
            String field = extractWhoisField(whois, 1);
            if (field != null) {
                return field;
            }
        }
        return "Domain not Found\n\n\nThe Registry database contains ONLY .COM, .NET, .EDU domains and Registrars.";
    }

    public String getRegistrarUrl(String domain) {
        this.domainName = domain;
        String whois = getWhois(domainName, "com");
        if (!whois.contains("No match for")) {
            String field = extractWhoisField(whois, 3);
            if (field != null) {
                return field;
            }
        }
        return "Domain not Found\n\n\nThe Registry database contains ONLY .COM, .NET, .EDU domains and Registrars.";
    }

    public String getUpdateDateRaw(String domain) {
        this.domainName = domain;
        String whois = getWhois(domainName, "com");
        if (!whois.contains("No match for")) {
            String field = extractWhoisField(whois, 4);
            if (field != null) {
                return field;
            }
        }
        return "Domain not Found\n\n\nThe Registry database contains ONLY .COM, .NET, .EDU domains and Registrars.";
    }

    public String getUpdateDayFormatted(String domain) {
        String formattedDate = "Error in Parsing";
        this.domainName = domain;
        String whois = getWhois(domainName, "com");
        if (!whois.contains("No match for")) {
            String date = extractWhoisField(whois, 4);
            if (date != null) {
                SimpleDateFormat dateFormat = createWhoisDateFormat();
                try {
                    Date parsedDate = dateFormat.parse(date);
                    dateFormat.applyPattern("dd:MM:yyyy HH:mm:ss");
                    formattedDate = dateFormat.format(parsedDate);
                } catch (Exception e) {
                    Log.w(TAG, "Failed to parse update date", e);
                }
            }
            return formattedDate;
        } else {
            return "Domain not Found\n\n\nThe Registry database contains ONLY .COM, .NET, .EDU domains and Registrars.";
        }
    }

    public String getCreationDateRaw(String domain) {
        this.domainName = domain;
        String whois = getWhois(domainName, "com");
        if (!whois.contains("No match for")) {
            String field = extractWhoisField(whois, 5);
            if (field != null) {
                return field;
            }
        }
        return "Domain not Found\n\n\nThe Registry database contains ONLY .COM, .NET, .EDU domains and Registrars.";
    }

    public String getCreationDayFormatted(String domain) {
        String formattedDate = "Error in Parsing";
        this.domainName = domain;
        String whois = getWhois(domainName, "com");
        if (!whois.contains("No match for")) {
            String date = extractWhoisField(whois, 5);
            if (date != null) {
                SimpleDateFormat dateFormat = createWhoisDateFormat();
                try {
                    Date parsedDate = dateFormat.parse(date);
                    dateFormat.applyPattern("dd:MM:yyyy HH:mm:ss");
                    formattedDate = dateFormat.format(parsedDate);
                } catch (Exception e) {
                    Log.w(TAG, "Failed to parse creation date", e);
                }
            }
            return formattedDate;
        } else {
            return "Domain not Found\n\n\nThe Registry database contains ONLY .COM, .NET, .EDU domains and Registrars.";
        }
    }

    public String getRegistryDomainId() {
        if (domainName == null) {
            return "Domain not Found\n\n\nThe Registry database contains ONLY .COM, .NET, .EDU domains and Registrars.";
        }
        String whois = getWhois(domainName, "com");
        String field = extractWhoisField(whois, 1);
        if (field != null) {
            return field;
        }
        return "Domain not Found\n\n\nThe Registry database contains ONLY .COM, .NET, .EDU domains and Registrars.";
    }
}
