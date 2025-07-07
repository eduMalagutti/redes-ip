from iputils import *
import struct


class IP:
    def __init__(self, enlace):
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.id = 0
        self.tabela_encaminhamento = {}
        self.prox = -1  # prefixo do melhor match mais recente

    def __raw_recv(self, datagrama):
        _, _, _, _, _, ttl, proto, src_addr, dst_addr, payload = read_ipv4_header(datagrama)

        if dst_addr == self.meu_endereco:
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            self.prox = -1
            next_hop = self._next_hop(dst_addr)

            verNheader, dscpNecn, length, _, flagNfrag, _, protocolo, _, orig, dest = struct.unpack('!BBHHHBBHII', datagrama[:20])

            if ttl > 1:
                prev_exec = [verNheader, dscpNecn, length, self.id, flagNfrag, ttl, protocolo, 0, orig, dest]
                datagrama = self.buildDatagram(payload, None, prev_exec)
            else:
                protocolo = IPPROTO_ICMP
                self.prox = -1
                next_hop = self._next_hop(src_addr)

                dest = next_hop
                if self.prox == 0:
                    dest = src_addr

                orig, = struct.unpack('!I', str2addr(self.meu_endereco))
                dest, = struct.unpack('!I', str2addr(dest))

                prev_exec = [verNheader, dscpNecn, length, self.id, flagNfrag, 64, protocolo, 0, orig, dest]

                type = 11  # ICMP Time Exceeded
                code = 0
                checksum = 0
                unused = 0
                ihl = verNheader & 0x0f
                tam = 8 + (4 * ihl)

                icmp_header = struct.pack('!BBHI', type, code, checksum, unused) + datagrama[:tam]
                checksum = calc_checksum(icmp_header)
                icmp_header = struct.pack('!BBHI', type, code, checksum, unused) + datagrama[:tam]

                prev_exec[2] = len(icmp_header) + 20
                datagrama = self.buildDatagram(icmp_header, None, prev_exec)
                self.enlace.enviar(datagrama, next_hop)
                return

            self.enlace.enviar(datagrama, next_hop)

    def _next_hop(self, dest_addr):
        destino, = struct.unpack('!I', str2addr(dest_addr))
        for key in self.tabela_encaminhamento.keys():
            cidr, bits_prefix = key.split('/')
            prefix = int(bits_prefix)
            bits_prefix = 32 - prefix
            cidr, = struct.unpack('!I', str2addr(cidr))
            cidr = cidr >> bits_prefix << bits_prefix
            dest = destino >> bits_prefix << bits_prefix

            if dest == cidr:
                self.prox = prefix
                return self.tabela_encaminhamento[key]

    def definir_endereco_host(self, meu_endereco):
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        if len(self.tabela_encaminhamento) != 0:
            self.tabela_encaminhamento.clear()

        tabela.sort(key=self.get_prefix_length, reverse=True)

        for endereco in tabela:
            self.tabela_encaminhamento[endereco[0]] = endereco[1]

    def get_prefix_length(self, bits):
        return int(bits[0].split('/')[1])

    def registrar_recebedor(self, callback):
        self.callback = callback

    def buildDatagram(self, segmento, dest_addr, prev_exec=None):
        if prev_exec is None:
            verNheader = 0x45
            dscpNecn = 0x00
            length = 20 + len(segmento)
            address = self.id
            flagNfrag = 0x00
            ttl = 64
            protocolo = IPPROTO_TCP
            checksum = 0
            orig, = struct.unpack('!I', str2addr(self.meu_endereco))
            dest, = struct.unpack('!I', str2addr(dest_addr))
            self.id += length
        else:
            verNheader, dscpNecn, length, address, flagNfrag, ttl, protocolo, checksum, orig, dest = prev_exec
            ttl -= 1

        header = struct.pack('!BBHHHBBHII', verNheader, dscpNecn, length, address,
                             flagNfrag, ttl, protocolo, checksum, orig, dest)
        checksum = calc_checksum(header)

        header = struct.pack('!BBHHHBBHII', verNheader, dscpNecn, length, address,
                             flagNfrag, ttl, protocolo, checksum, orig, dest)

        return header + segmento

    def enviar(self, segmento, dest_addr):
        next_hop = self._next_hop(dest_addr)
        datagrama = self.buildDatagram(segmento, dest_addr)
        self.enlace.enviar(datagrama, next_hop)
