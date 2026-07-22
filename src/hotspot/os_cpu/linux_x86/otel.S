	.intel_syntax noprefix
	.text
	.p2align 4,,15
	.globl	writeOpenTelemetryTLS0
	.type	writeOpenTelemetryTLS0, @function
writeOpenTelemetryTLS0:
.LFB0:
	.cfi_startproc
	push	rbx
	.cfi_def_cfa_offset 16
	.cfi_offset 3, -16
	mov	rbx, rdi
	.byte	0x66
	lea	rdi, otel_thread_ctx_v1@tlsgd[rip]
	.value	0x6666
	rex64
	call	__tls_get_addr@PLT
	mov	rcx, rax
	mov	rax, QWORD PTR [rax]
	mov	QWORD PTR [rcx], rbx
	pop	rbx
	.cfi_def_cfa_offset 8
	ret
	.cfi_endproc
.LFE0:
	.size	writeOpenTelemetryTLS0, .-writeOpenTelemetryTLS0

//	.globl	otel_thread_ctx_v1
//	.section	.tbss,"awT",@nobits
//	.align 8
//	.type	otel_thread_ctx_v1, @object
//	.size	otel_thread_ctx_v1, 8
//otel_thread_ctx_v1:
//	.zero	8
