	.intel_syntax noprefix
	.text
	.p2align 4,,15
	.globl	writeOpenTelemetryTLS0
	.type	writeOpenTelemetryTLS0, @function
writeOpenTelemetryTLS0:
.LFB0:
	.cfi_startproc
	sub	rsp, 8
	.cfi_def_cfa_offset 16
	lea	rax, otel_thread_ctx_v1@TLSDESC[rip]
	mov	rcx, rdi
	call	[QWORD PTR [rax+otel_thread_ctx_v1@TLSCALL]]
	add	rax, QWORD PTR fs:0
	mov	rdx, QWORD PTR [rax]
	mov	QWORD PTR [rax], rcx
	add	rsp, 8
	.cfi_def_cfa_offset 8
	mov	rax, rdx
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
