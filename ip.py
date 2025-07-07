from iputils import *
import struct

class IP:
    def __init__(self, enlace):
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.tabela = []

    def __raw_recv(self, datagrama):
        try:
            dscp, ecn, identification, flags, frag_offset, ttl, proto, \
            src_addr, dst_addr, payload = read_ipv4_header(datagrama, verify_checksum=not self.ignore_checksum)
        except ValueError:
            return

        # Se o pacote é para mim, entrega à aplicação
        if dst_addr == self.meu_endereco:
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
            return

        # Encaminhamento: decrementa TTL e reenvia
        ttl -= 1
        if ttl <= 0:
            self._enviar_icmp_time_exceeded(datagrama, src_addr)
            return

        next_hop = self._next_hop(dst_addr)
        if next_hop is None:
            return

        novo_datagrama = self._recriar_datagrama(datagrama, ttl)
        self.enlace.enviar(novo_datagrama, next_hop)

    def _next_hop(self, dest_addr):
        dest_int = struct.unpack('!I', str2addr(dest_addr))[0]
        melhor_prefixo = -1
        proximo = None
        for cidr, nhop in self.tabela:
            rede_str, prefixo_str = cidr.split('/')
            prefixo = int(prefixo_str)
            mask = (0xffffffff << (32 - prefixo)) & 0xffffffff
            rede_int = struct.unpack('!I', str2addr(rede_str))[0]
            if (dest_int & mask) == (rede_int & mask):
                if prefixo > melhor_prefixo:
                    melhor_prefixo = prefixo
                    proximo = nhop
        return proximo

    def definir_tabela_encaminhamento(self, tabela):
        self.tabela = tabela

    def definir_endereco_host(self, meu_endereco):
        self.meu_endereco = meu_endereco

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        next_hop = self._next_hop(dest_addr)
        if next_hop is None:
            return

        version = 4
        ihl = 5
        vihl = (version << 4) + ihl
        dscpecn = 0
        total_len = 20 + len(segmento)
        identification = 0
        flags = 0
        frag_offset = 0
        ttl = 64
        proto = IPPROTO_TCP
        src = str2addr(self.meu_endereco)
        dst = str2addr(dest_addr)

        header_sem_checksum = struct.pack('!BBHHHBBH4s4s',
                                vihl,
                                dscpecn,
                                total_len,
                                identification,
                                (flags << 13) | frag_offset,
                                ttl,
                                proto,
                                0,
                                src,
                                dst)
        checksum = calc_checksum(header_sem_checksum)

        datagrama = struct.pack('!BBHHHBBH4s4s',
                                vihl,
                                dscpecn,
                                total_len,
                                identification,
                                (flags << 13) | frag_offset,
                                ttl,
                                proto,
                                checksum,
                                src,
                                dst)
        datagrama += segmento
        self.enlace.enviar(datagrama, next_hop)

    def _recriar_datagrama(self, datagrama, novo_ttl):
        header = datagrama[:20]
        campos = struct.unpack('!BBHHHBBH', header[:12])
        vihl, dscpecn, total_len, identification, flagsfrag, old_ttl, proto, checksum = campos
        src = header[12:16]
        dst = header[16:20]

        flags = (flagsfrag >> 13) & 0x7
        frag_offset = flagsfrag & 0x1FFF

        novo_header_sem_checksum = struct.pack('!BBHHHBBH4s4s',
                                  vihl,
                                  dscpecn,
                                  total_len,
                                  identification,
                                  (flags << 13) | frag_offset,
                                  novo_ttl,
                                  proto,
                                  0,
                                  src,
                                  dst)
        checksum = calc_checksum(novo_header_sem_checksum)

        novo_header = struct.pack('!BBHHHBBH4s4s',
                                  vihl,
                                  dscpecn,
                                  total_len,
                                  identification,
                                  (flags << 13) | frag_offset,
                                  novo_ttl,
                                  proto,
                                  checksum,
                                  src,
                                  dst)
        return novo_header + datagrama[20:]

    def _enviar_icmp_time_exceeded(self, datagrama_recebido, addr_destino):
        tipo = 11
        codigo = 0
        unused = 0
        payload_icmp = datagrama_recebido[:28]

        icmp_sem_checksum = struct.pack('!BBHI', tipo, codigo, 0, unused) + payload_icmp
        checksum_icmp = calc_checksum(icmp_sem_checksum)
        icmp = struct.pack('!BBHI', tipo, codigo, checksum_icmp, unused) + payload_icmp

        version = 4
        ihl = 5
        vihl = (version << 4) + ihl
        dscpecn = 0
        total_len = 20 + len(icmp)
        identification = 0
        flags = 0
        frag_offset = 0
        ttl = 64
        proto = IPPROTO_ICMP
        src = str2addr(self.meu_endereco)
        dst = str2addr(addr_destino)

        ip_header_sem_checksum = struct.pack('!BBHHHBBH4s4s',
                                vihl,
                                dscpecn,
                                total_len,
                                identification,
                                (flags << 13) | frag_offset,
                                ttl,
                                proto,
                                0,
                                src,
                                dst)
        checksum_ip = calc_checksum(ip_header_sem_checksum)
        ip_header = struct.pack('!BBHHHBBH4s4s',
                                vihl,
                                dscpecn,
                                total_len,
                                identification,
                                (flags << 13) | frag_offset,
                                ttl,
                                proto,
                                checksum_ip,
                                src,
                                dst)

        datagrama_icmp = ip_header + icmp
        next_hop = self._next_hop(addr_destino)
        if next_hop is not None:
            self.enlace.enviar(datagrama_icmp, next_hop)
