/*
    Single file parser
    Able to parse various kinds of sub
    Non-server required
    Deploy on cloudflare worker
    Features:
        Outbound Filter
            action : include or exclude
            keywords : regex of filtered
        Outbounds Select
            {sub} : all outbounds in sub
 */

const SubType = {
    SOCKS : 'SOCKS',
    HTTP : 'HTTP',
    SHADOWSOCKS : 'SHADOWSOCKS',
    VMESS : 'VMESS',
    TROJAN : 'TROJAN',
    HYSTERIA : 'HYSTERIA',
    HYSTERIA2 : 'HYSTERIA2',
    SHADOWTLS : 'SHADOWTLS',
    VLESS : 'VLESS',
    TUIC : 'TUIC',
}

const ConnProtocol = {
    TCP : 'TCP',
    UDP : 'UDP',
    KCP : 'KCP',
    WS : 'WS',
    H2 : 'H2',
    QUIC : 'QUIC',
}

/**
 * @function stoConnProtocol Convert string to ConnProtocol
 * @param s {string}
 * @return string
 */
function stoConnProtocol(s) {
    return ConnProtocol[s.toUpperCase()];
}

class Node {
    /**
     * @function Node Constructor
     * @param type {string} Type of node
     * @param connProtocol {string} protocol
     * @param hostName {string} Host name of node
     * @param port {string} Port of node
     * @param description {string} Desperation of node
     */
    constructor(type, connProtocol, hostName, port, description) {
        this.subType = type;
        this.connProtocol = connProtocol === undefined ? ConnProtocol.TCP : connProtocol;
        this.hostName = hostName;
        this.port = port;
        this.description = description;
    }
}

class NodeVMESS extends Node {
    /**
     * @function NodeVMESS Constructor
     * @param connProtocol {string} protocol
     * @param hostName {string} Host name of node
     * @param port {string} Port of node
     * @param uuid {string} UUID of node
     * @param aid {string} alterid
     * @param seq {string} security encrypt method
     * @param tls {string} tls
     * @param sni {string} sni
     * @param fp {string} fingerprint
     * @param alpn {string} h2, http/1.1
     * @param description {string} Desperation of node
     */
    constructor(connProtocol, hostName, port, uuid, aid, seq, tls, sni, fp, alpn, description) {
        super(SubType.VMESS, connProtocol, hostName, port, description);
        this.uuid = uuid;
        this.aid = aid;
        this.seq = seq;
        this.tls = tls;
        this.sni = sni;
        this.fp = fp;
        this.alpn = alpn;
    }
}

/**
 * @function pareseVmess Parse vmess to node
 * @param uri {string} Raw URI. e.g.vmess://[BASE64]
 * @return Node {null if invalid}
 */
function parseVMESS(uri) {
    let url = new URL(uri);
    if(url.protocol !== "vmess:") {
        return null;
    }
    let jsonObj = JSON.parse(atob(url.hostname));
    return new NodeVMESS(stoConnProtocol(jsonObj["net"] === undefined ? "TCP" : jsonObj["net"]), jsonObj["add"], jsonObj["port"], jsonObj["id"], jsonObj["aid"], jsonObj["scy"], jsonObj["tls"], jsonObj["sni"], jsonObj["fp"], jsonObj["alpn"], jsonObj["ps"]);
}

class NodeTrojan extends Node {
    /**
     * @function NodeTrojan Constructor
     * @param connProtocol {string} protocol
     * @param hostName {string} Host name of node
     * @param port {string} Port of node
     * @param pass {string} password of node
     * @param allowInsecure {string} allow insecure connect or not
     * @param alpn {string}
     * @param description {string} Desperation of node
     */
    constructor(connProtocol, hostName, port, pass, allowInsecure, alpn, description) {
        super(SubType.TROJAN, connProtocol, hostName, port, description);
        this.pass = pass;
        this.allowInsecure = allowInsecure;
        this.alpn = alpn;
    }
}

/**
 * @function parseTrojan Parse trojan to node
 * @param uri {string} Raw URI. e.g.trojan://
 * @return Node {null if invalid}
 */
function parseTrojan(uri) {
    let url = new URL(uri);
    if(url.protocol !== "trojan:") {
        return null;
    }
    return new NodeTrojan(stoConnProtocol(url.searchParams.get("type") == null ? "TCP" : url.searchParams.get("type")), url.hostname, url.port, url.password, url.searchParams.get("allowInsecure"), decodeURIComponent(url.searchParams.get("alpn")), decodeURIComponent(url.searchParams.get("name")));
}

class NodeVLESS extends Node {
    /**
     * @function NodeVLESS Constructor
     * @param connProtocol {string} protocol
     * @param hostName {string} Host name of node
     * @param port {string} Port of node
     * @param uuid {string} UUID of node
     * @param flow {string} sub-protocol
     * @param seq {string} security method
     * @param encrypt {string} encrypt method
     * @param sni {string} sni
     * @param fp {string} fingerprint
     * @param alpn {string} h2, http/1.1
     * @param description {string} Desperation of node
     */
    constructor(connProtocol, hostName, port, uuid, flow, seq, encrypt, sni, fp, alpn, description) {
        super(SubType.VLESS, connProtocol, hostName, port, description);
        this.uuid = uuid;
        this.flow = flow;
        this.seq = seq;
        this.encrypt = encrypt;
        this.sni = sni;
        this.fp = fp;
        this.alpn = alpn;
    }
}

/**
 * @function parseTrojan Parse trojan to node
 * @param uri {string} Raw URI. e.g.vless://
 * @return Node {null if invalid}
 */
function parseVLESS(uri) {
    let url = new URL(uri);
    if(url.protocol !== "vless:") {
        return null;
    }
    return new NodeVLESS(stoConnProtocol(url.searchParams.get("type") == null ? "TCP" : url.searchParams.get("type")), url.hostname, url.port, decodeURIComponent(url.username), url.searchParams.get("flow"), url.searchParams.get("security"), url.searchParams.get("encryption"), url.searchParams.get("sni"), url.searchParams.get("fp"), decodeURIComponent(url.searchParams.get("alpn")), decodeURIComponent(url.searchParams.get("descriptive-text") == null ? url.hash : url.searchParams.get("descriptive-text")));
}

class NodeTUIC extends Node {
    /**
     * @function NodeTUIC Constructor
     * @param connProtocol {string} protocol
     * @param hostName {string} Host name of node
     * @param port {string} Port of node
     * @param uuid {string} UUID of node
     * @param pass {string} password of node
     * @param udp_relay_mode {string} UDP relay mode
     * @param congestion_control {string} Congestion control
     * @param allowInsecure {string} allow insecure connect or not
     * @param description {string} Desperation of node
     */
    constructor(connProtocol, hostName, port, uuid, pass, udp_relay_mode, congestion_control, allowInsecure, description) {
        super(SubType.TUIC, connProtocol, hostName, port, description);
        this.uuid = uuid;
        this.pass = pass;
        this.udp_relay_mode = udp_relay_mode;
        this.congestion_control = congestion_control;
        this.allowInsecure = allowInsecure;
        this.description = description;
    }
}

/**
 * @function parseTrojan Parse trojan to node
 * @param uri {string} Raw URI. e.g.tuic://
 * @return Node {null if invalid}
 */
function parseTUIC(uri) {
    let url = new URL(uri);
    if(url.protocol !== "tuic:") {
        return null;
    }
    return new NodeTUIC(ConnProtocol.QUIC, url.hostname, url.port, decodeURIComponent(url.username), url.password, url.searchParams.get("udp_relay_mode"), url.searchParams.get("congestion_control"), url.searchParams.get("allow_insecure"), url.hash);
}

class NodeHysteria extends Node {
    /**
     * @function NodeHysteria Constructor
     * @param connProtocol {string} protocol
     * @param hostName {string} Host name of node
     * @param port {string} Port of node
     * @param auth {string} auth
     * @param allowInsecure {string} allow insecure connect or not
     * @param upmbps {string} Up Mbps
     * @param downmbps {string} Down Mbps
     * @param obfs {string} Obfuscation
     * @param sni {string} sni
     * @param alpn {string} h2, http/1.1
     * @param description {string} Desperation of node
     */
    constructor(connProtocol, hostName, port, auth, allowInsecure, upmbps, downmbps, sni, obfs, alpn, description) {
        super(SubType.HYSTERIA, connProtocol, hostName, port, description);
        this.auth = auth;
        this.allowInsecure = allowInsecure;
        this.upmbps = upmbps;
        this.downmbps = downmbps;
        this.sni = sni;
        this.obfs = obfs;
        this.alpn = alpn;
    }
}

/**
 * @function parseTrojan Parse Hysteria to node
 * @param uri {string} Raw URI. e.g.hysteria://
 * @return Node {null if invalid}
 */
function parseHysteria(uri) {
    let url = new URL(uri);
    if(url.protocol !== "hysteria:") {
        return null;
    }
    return new NodeHysteria(stoConnProtocol(url.searchParams.get("protocol") == null ? "QUIC" : url.searchParams.get("protocol")), url.hostname, url.port, url.searchParams.get("auth"), url.searchParams.get("insecure"), url.searchParams.get("upmbps"), url.searchParams.get("downmbps"), url.searchParams.get("peer"), decodeURIComponent(url.searchParams.get("obfs")), url.searchParams.get("alpn"), url.hash);
}

class NodeHysteria2 extends Node {
    /**
     * @function NodeHysteria2 Constructor
     * @param connProtocol {string} protocol
     * @param hostName {string} Host name of node
     * @param port {string} Port of node
     * @param auth {string} auth
     * @param allowInsecure {string} allow insecure connect or not
     * @param upmbps {string} Up Mbps
     * @param downmbps {string} Down Mbps
     * @param obfs {string} Obfuscation
     * @param obfsPassword {string} Obfuscation pass
     * @param sni {string} sni
     * @param fp {string} fingerprint (pinSHA256)
     * @param alpn {string} h2, http/1.1
     * @param description {string} Desperation of node
     */
    constructor(connProtocol, hostName, port, auth, allowInsecure, upmbps, downmbps, sni, obfs, obfsPassword, fp, alpn, description) {
        super(SubType.HYSTERIA2, connProtocol, hostName, port, description);
        this.auth = auth;
        this.allowInsecure = allowInsecure;
        this.upmbps = upmbps;
        this.downmbps = downmbps;
        this.sni = sni;
        this.obfs = obfs;
        this.obfsPassword = obfsPassword;
        this.fp = fp;
        this.alpn = alpn;
    }
}

/**
 * @function parseTrojan Parse Hysteria to node
 * @param uri {string} Raw URI. e.g.hysteria://
 * @return Node {null if invalid}
 */
function parseHysteria2(uri) {
    let url = new URL(uri);
    if(url.protocol !== "hysteria2:") {
        return null;
    }
    return new NodeHysteria2(stoConnProtocol(url.searchParams.get("protocol") == null ? "QUIC" : url.searchParams.get("protocol")), url.hostname, url.port, url.password, url.searchParams.get("insecure"), url.searchParams.get("upmbps"), url.searchParams.get("downmbps"), url.searchParams.get("sni"), decodeURIComponent(url.searchParams.get("obfs")), url.searchParams.get("obfs-password"), url.searchParams.get("pinSHA256"), url.searchParams.get("alpn"), url.hash);
}

class NodeHTTP extends Node {
    /**
     * @function NodeHTTP Constructor
     * @param hostName {string} Host name of node
     * @param port {string} Port of node
     * @param user {string} Username
     * @param pass {string} password of node
     * @param description {string} Desperation of node
     */
    constructor(hostName, port, user, pass, description) {
        super(SubType.HTTP, ConnProtocol.TCP, hostName, port, description);
        this.user = user;
        this.pass = pass;
    }
}

/**
 * @function parseHTTP Parse trojan to node
 * @param uri {string} Raw URI. e.g.http://
 * @return Node {null if invalid}
 */
function parseHTTP(uri) {
    let url = new URL(uri);
    if(url.protocol !== "http:") {
        return null;
    }
    return new NodeHTTP(url.hostname, url.port, url.username, url.password, url.hash);
}

function genTLS(sni, fp, alpn, insecure) {
    if(alpn != null) {
        return {
            "enabled": true,
            "insecure": insecure === 1,
            "alpn": alpn.split(","),
        }
    }
    return {
        "enabled": true,
        "insecure": insecure === 1,
    }
}

export default {
    async fetch(request, env, ctx){
        const requrl = new URL(request.url);
        let params = requrl.searchParams;
        //const keyRequired = true;
        /*
        if (requrl.startsWith("/sign")) {
            let authkey = params.get("Key");
            let sign = new JSEncrypt();
            sign.setPrivateKey(authkey);
            let signed = sign.sign("SingboxParser", CryptoJS().SHA256, "sha256");

            return new Response(`{"key": "${signed}"}`, {
                headers: {
                    "content-type": "application/json",
                }, status: 200
            })
        }
        */

        if (requrl.pathname !== "/parse") {
            return new Response(`error: i'm a teapot`, {
                headers: {
                    "content-type" : "text/plain",
                }, status: 405
            });
        }

        if (!params.has("config") || !params.has("template")) {
            return new Response(`400 Bad Request`, {
                headers: {
                    "content-type": "text/plain",
                }, status: 400
            })
        }

        /*
        if(keyRequired) {
            let authstr = params.get("Auth");
            if (authstr == null) authstr = "SingboxParser";
            let authkey = params.get("Key");

            if (authkey == null) {
                return new Response(`error: Authorize failed`, {
                    headers: {
                        "content-type" : "text/plain",
                    }, status: 403
                });
            }

            let verify = new JSEncrypt();
            verify.setPublicKey("");
            let valided = verify.verify(authstr, authkey, CryptoJS().SHA256);
            if (!valided) {
                return new Response(`error: Authorize failed`, {
                    headers: {
                        "content-type" : "text/plain",
                    }, status: 403
                });
            }
        }
        */

        let configURL = atob(params.get("config"));
        let templateURL = atob(params.get("template"));

        let configResp = await fetch(configURL);
        let templateResp = await fetch(templateURL);

        if (configResp.status !== 200 || templateResp.status !== 200) {
            return new Response(`error: Fetch error, config ${configResp.status}, template ${templateResp.status}`, {
                headers: {
                    "content-type": "text/plain",
                }, status: configResp.status
            })
        }

        let rawconfig = await configResp.text();
        let rawtemplate = await templateResp.text();

        let configObj = JSON.parse(rawtemplate);
        let subscriptions = atob(rawconfig).split("\r\n");
        let nodes = [];


        subscriptions.forEach((str) => {
            if(str === "") return;
            let url = new URL(str);
            switch(url.protocol) {
                case "vmess:":
                    nodes.push(parseVMESS(str));
                    break;
                case "trojan:":
                    nodes.push(parseTrojan(str));
                    break;
                case "vless:":
                    nodes.push(parseVLESS(str));
                    break;
                case "tuic:":
                    nodes.push(parseTUIC(str));
                    break;
                case "hysteria:":
                    nodes.push(parseHysteria(str));
                    break;
                case "hysteria2:":
                    nodes.push(parseHysteria2(str));
                    break;
                case "http:":
                    nodes.push(parseHTTP(str));
                    break;
            }
        });

        let usedNodes = [];

        configObj["outbounds"].forEach((dic) => {
            if(dic["filter"] !== undefined && dic["outbounds"].includes("{sub}")) {
                let currentNodes = []
                let regInc;
                let regExc;
                dic["filter"].forEach((dic0) => {
                    if(dic0["action"] === "include") regInc = new RegExp(dic0["regex"][0]);
                    else regExc = new RegExp(dic0["regex"][0]);
                });

                nodes.forEach((node) => {
                    let flagInc = true;
                    let flagExc = true;

                    if(regInc != null) flagInc = regInc.test(node.description);
                    if(regExc != null) flagExc = !(regExc.test(node.description));

                    if(flagInc && flagExc) {
                        currentNodes.push(node);
                        if(!usedNodes.includes(node)) usedNodes.push(node);
                    }
                });

                currentNodes.forEach((node) => {
                    dic["outbounds"].push(node.description);
                });
            }
        });

        usedNodes.forEach((node) => {
            switch (node.subType) {
                case SubType.VMESS:
                    if(node.tls !== "tls") {
                        configObj["outbounds"].push({
                            "type": node.subType,
                            "tag": node.description,
                            "server": node.hostName,
                            "server_port": parseInt(node.port),
                            "uuid": node.uuid,
                            "security": node.seq === undefined ? "auto" : node.seq,
                            "alter_id": node.aid,
                            "network": node.connProtocol,
                        });
                    }else {
                        configObj["outbounds"].push({
                            "type": node.subType,
                            "tag": node.description,
                            "server": node.hostName,
                            "server_port": parseInt(node.port),
                            "uuid": node.uuid,
                            "security": node.seq === undefined ? "auto" : node.seq,
                            "alter_id": node.aid,
                            "network": node.connProtocol,
                            "tls": genTLS(node.sni, node.fp, node.alpn, false),
                        });
                    }

                    break;
                case SubType.TROJAN:
                    configObj["outbounds"].push({
                        "type": node.subType,
                        "tag": node.description,
                        "server": node.hostName,
                        "server_port": parseInt(node.port),
                        "password": node.pass,
                        "network": node.connProtocol,
                        "tls": genTLS(null, null, node.alpn, node.allowInsecure),
                    });
                    break;
                case SubType.VLESS:
                    if(node.security === "tls") {
                        configObj["outbounds"].push({
                            "type": node.subType,
                            "tag": node.description,
                            "server": node.hostName,
                            "server_port": parseInt(node.port),
                            "uuid": node.uuid,
                            "flow": node.flow,
                            "network": node.connProtocol,
                            "tls": genTLS(node.sni, node.fp, node.alpn, false)
                        });
                    }else {
                        configObj["outbounds"].push({
                            "type": node.subType,
                            "tag": node.description,
                            "server": node.hostName,
                            "server_port": parseInt(node.port),
                            "uuid": node.uuid,
                            "flow": node.flow,
                            "network": node.connProtocol,
                        });
                    }

                    break;
                case SubType.TUIC:
                    configObj["outbounds"].push({
                        "type": node.subType,
                        "tag": node.description,
                        "server": node.hostName,
                        "server_port": parseInt(node.port),
                        "uuid": node.uuid,
                        "password": node.pass,
                        "network": node.connProtocol,
                        "udp_relay_mode": node.udp_relay_mode,
                        "congestion_control": node.congestion_control,
                        "tls": genTLS(null, null, null, false)
                    });
                    break;
                case SubType.HYSTERIA:
                    configObj["outbounds"].push({
                        "type": node.subType,
                        "tag": node.description,
                        "server": node.hostName,
                        "server_port": parseInt(node.port),
                        "up": node.upmbps + " Mbps",
                        "up_mbps": parseInt(node.upmbps),
                        "down": node.downmbps + " Mbps",
                        "down_mbps": parseInt(node.downmbps),
                        "obfs": node.obfs,
                        "network": node.connProtocol,
                        "tls": genTLS(node.sni, null, node.alpn, node.allowInsecure)
                    });
                    break;
                case SubType.HYSTERIA2:
                    configObj["outbounds"].push({
                        "type": node.subType,
                        "tag": node.description,
                        "server": node.hostName,
                        "server_port": parseInt(node.port),
                        "up": node.upmbps + " Mbps",
                        "up_mbps": parseInt(node.upmbps),
                        "down": node.downmbps + " Mbps",
                        "down_mbps": parseInt(node.downmbps),
                        "obfs": {
                            "type": node.obfs != null ? "salamander" : "",
                            "password": node.obfsPassword
                        },
                        "password": node.auth,
                        "network": node.connProtocol,
                        "tls": genTLS(node.sni, node.fp, node.alpn, node.allowInsecure)
                    });
                    break;
            }
        });
        return new Response(JSON.stringify(configObj), {
            headers: {
                "content-type": "application/json",
            }, status: 200
        })
    }
}