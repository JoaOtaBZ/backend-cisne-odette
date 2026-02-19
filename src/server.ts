// server.ts
//
// API Express + Prisma para autenticação, cadastro de escolas e gestão de usuários.
// Estrutura:
// - Validação de env
// - Middlewares (CORS, JSON, auth)
// - Helpers (sanitização/validação)
// - Rotas (health, dev seed, auth, me, schools)
// - Start

import dotenv from "dotenv";
dotenv.config();

import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { PrismaClient } from "@prisma/client";

/* ================== VALIDAÇÃO ENV ================== */

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL não está definida no .env");
}
if (!process.env.JWT_SECRET) {
  throw new Error("JWT_SECRET não está definida no .env");
}

const app = express();
const prisma = new PrismaClient();

app.use(cors({
  origin: (origin, cb) => cb(null, true),
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));

app.options(/.*/, cors());

app.use(express.json());

/* ================== HELPERS ================== */

function paramStr(value: unknown): string | null {
  if (typeof value === "string") return value;
  if (Array.isArray(value) && typeof value[0] === "string") return value[0];
  return null;
}

function isValidEmail(email: string) {
  return /^\S+@\S+\.\S+$/.test(email);
}

function cleanEmail(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const e = value.trim().toLowerCase();
  return e.length ? e : undefined;
}

/**
 * Phone:
 * - undefined => "não enviado" (não atualiza)
 * - null => apaga (para campos que aceitam null)
 * - string => retorna somente dígitos (10 ou 11)
 * - "__INVALID__" => marcador de inválido
 */
function cleanPhone(value: unknown): string | null | undefined | "__INVALID__" {
  if (value === undefined) return undefined;
  if (value === null) return null;
  if (typeof value !== "string") return undefined;

  let digits = value.replace(/\D/g, "");

  // Se colarem +55..., remove
  if (digits.startsWith("55") && (digits.length === 12 || digits.length === 13)) {
    digits = digits.slice(2);
  }

  if (!(digits.length === 10 || digits.length === 11)) {
    return "__INVALID__";
  }

  return digits;
}

type JwtPayload = {
  sub: string;
  schoolId: string;
  email: string;
  isAdmin?: boolean;
  iat?: number;
  exp?: number;
};

function requireAuth(req: Request, res: Response, next: NextFunction) {
  const auth = req.headers.authorization;

  if (!auth || !auth.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Não autenticado" });
  }

  const token = auth.slice(7);

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET as string) as JwtPayload;
    (req as any).user = payload;
    return next();
  } catch {
    return res.status(401).json({ error: "Token inválido" });
  }
}

function requireAdmin(req: Request, res: Response, next: NextFunction) {
  const isAdmin = Boolean((req as any).user?.isAdmin);
  if (!isAdmin) {
    return res.status(403).json({ error: "Apenas admin" });
  }
  return next();
}

function canAccessSchool(req: Request, schoolId: string) {
  const tokenSchoolId = (req as any).user?.schoolId as string | undefined;
  const isAdmin = Boolean((req as any).user?.isAdmin);

  if (isAdmin) return true;
  if (!tokenSchoolId) return false;

  return tokenSchoolId === schoolId;
}

/* ================== ROTAS BÁSICAS ================== */

app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

/* ================== DEV: SEED ADMIN ================== */

app.post("/dev/seed-admin", async (_req, res) => {
  try {
    const existing = await prisma.user.findUnique({
      where: { email: "admin@local.com" },
    });

    if (existing) {
      return res.json({
        ok: true,
        message: "Admin já existe",
        email: existing.email,
        userId: existing.id,
        schoolId: existing.schoolId,
        isAdmin: existing.isAdmin,
      });
    }

    const school = await prisma.school.create({
      data: {
        name: "Escola Admin",
        responsible: "Admin",
        email: "school-admin@local.com",
        phone: "0000000000",
        royaltiesFee: 0,
        payDay: 1,
      },
    });

    const passwordHash = await bcrypt.hash("admin123", 10);

    const admin = await prisma.user.create({
      data: {
        name: "Admin",
        email: "admin@local.com",
        phone: "0000000000",
        passwordHash,
        tempPassword: false,
        schoolId: school.id,
        isAdmin: true,
      },
    });

    return res.json({
      ok: true,
      email: admin.email,
      password: "admin123",
      userId: admin.id,
      schoolId: school.id,
      isAdmin: true,
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Erro ao seed" });
  }
});

/* ================== AUTH ================== */

/** LOGIN */
app.post("/auth/login", async (req, res) => {
  try {
    const email = cleanEmail(req.body?.email);
    const password = typeof req.body?.password === "string" ? req.body.password : undefined;

    if (!email || !password) {
      return res.status(400).json({ error: "Email e senha são obrigatórios" });
    }

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(401).json({ error: "Credenciais inválidas" });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: "Credenciais inválidas" });

    const token = jwt.sign(
      {
        sub: user.id,
        schoolId: user.schoolId,
        email: user.email,
        isAdmin: user.isAdmin,
      },
      process.env.JWT_SECRET as string,
      { expiresIn: "8h" }
    );

    return res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        schoolId: user.schoolId,
        tempPassword: user.tempPassword,
        isAdmin: user.isAdmin,
      },
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Erro ao fazer login" });
  }
});

/** TROCAR SENHA (usuário logado) */
app.post("/auth/change-password", requireAuth, async (req, res) => {
  try {
    const { newPassword } = req.body as { newPassword?: string };
    const userId = (req as any).user?.sub as string | undefined;

    if (!userId) return res.status(401).json({ error: "Token inválido (sem sub)" });

    if (!newPassword || typeof newPassword !== "string" || newPassword.length < 6) {
      return res.status(400).json({ error: "Senha deve ter no mínimo 6 caracteres" });
    }

    const passwordHash = await bcrypt.hash(newPassword, 10);

    await prisma.user.update({
      where: { id: userId },
      data: { passwordHash, tempPassword: false },
    });

    return res.json({ ok: true });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Erro ao trocar senha" });
  }
});

/* ================== ME ================== */

/** Retorna dados do usuário logado */
app.get("/me", requireAuth, async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.sub as string | undefined;
    if (!userId) return res.status(401).json({ error: "Token inválido (sem sub)" });

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        name: true,
        email: true,
        phone: true,
        tempPassword: true,
        schoolId: true,
        isAdmin: true,
        createdAt: true,
      },
    });

    if (!user) return res.status(404).json({ error: "Usuário não encontrado" });

    return res.json({ user });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Erro ao buscar usuário" });
  }
});

/** Atualiza meus dados (email/telefone) */
app.patch("/me", requireAuth, async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.sub as string | undefined;
    if (!userId) return res.status(401).json({ error: "Token inválido (sem sub)" });

    const email = cleanEmail(req.body?.email);
    const phone = cleanPhone(req.body?.phone);

    if (!email && phone === undefined) {
      return res.status(400).json({ error: "Envie email e/ou phone" });
    }

    if (email && !isValidEmail(email)) {
      return res.status(400).json({ error: "E-mail inválido" });
    }

    if (phone === "__INVALID__") {
      return res.status(400).json({ error: "Telefone inválido (use DDD + número)" });
    }

    const updated = await prisma.user.update({
      where: { id: userId },
      data: {
        ...(email ? { email } : {}),
        ...(phone !== undefined ? { phone } : {}),
      },
      select: { id: true, name: true, email: true, phone: true, tempPassword: true, schoolId: true },
    });

    return res.json({ ok: true, user: updated });
  } catch (err: any) {
    if (err?.code === "P2002") {
      return res.status(409).json({ error: "E-mail já está em uso" });
    }
    console.error(err);
    return res.status(500).json({ error: "Erro ao atualizar dados" });
  }
});

/* ================== ESCOLA DO USUÁRIO ================== */

/** Retorna escola do usuário logado */
app.get("/me/school", requireAuth, async (req: Request, res: Response) => {
  try {
    const schoolId = (req as any).user?.schoolId as string | undefined;
    if (!schoolId) return res.status(400).json({ error: "schoolId não encontrado no token" });

    const school = await prisma.school.findUnique({
      where: { id: schoolId },
      select: {
        id: true,
        name: true,
        responsible: true,
        email: true,
        phone: true,
        royaltiesFee: true,
        payDay: true,
        cep: true,
        city: true,
        uf: true,
        neighborhood: true,
        createdAt: true,
      },
    });

    if (!school) return res.status(404).json({ error: "Escola não encontrada" });

    return res.json({ school });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Erro ao buscar escola" });
  }
});

/**
 * Atualiza e-mail/telefone da escola do usuário logado.
 * Observação: aqui não alteramos endereço (CEP/cidade/UF/bairro) porque no seu fluxo
 * quem edita tudo isso é o admin na rota /schools/:schoolId.
 */
app.patch("/me/school", requireAuth, async (req: Request, res: Response) => {
  try {
    const schoolId = (req as any).user?.schoolId as string | undefined;
    if (!schoolId) return res.status(400).json({ error: "schoolId não encontrado no token" });

    const email = cleanEmail(req.body?.email);
    const phone = cleanPhone(req.body?.phone);

    if (!email && phone === undefined) {
      return res.status(400).json({ error: "Envie email e/ou phone" });
    }

    if (email && !isValidEmail(email)) {
      return res.status(400).json({ error: "E-mail inválido" });
    }

    if (phone === "__INVALID__") {
      return res.status(400).json({ error: "Telefone inválido (use DDD + número)" });
    }

    // Para escola, phone normalmente é obrigatório (string no schema). Se vier null, rejeita.
    if (phone === null) {
      return res.status(400).json({ error: "Telefone da escola não pode ser vazio" });
    }

    const updated = await prisma.school.update({
      where: { id: schoolId },
      data: {
        ...(email ? { email } : {}),
        ...(phone !== undefined ? { phone } : {}),
      },
      select: {
        id: true,
        name: true,
        responsible: true,
        email: true,
        phone: true,
        royaltiesFee: true,
        payDay: true,
        cep: true,
        city: true,
        uf: true,
        neighborhood: true,
        createdAt: true,
      },
    });

    return res.json({ ok: true, school: updated });
  } catch (err: any) {
    if (err?.code === "P2002") {
      return res.status(409).json({ error: "E-mail já está em uso" });
    }
    console.error(err);
    return res.status(500).json({ error: "Erro ao atualizar escola" });
  }
});

/* ================== ADMIN: SCHOOLS ================== */

/** Buscar detalhes de uma escola (admin) */
app.get("/schools/:schoolId", requireAuth, requireAdmin, async (req, res) => {
  try {
    const schoolId = paramStr(req.params.schoolId);
    if (!schoolId) return res.status(400).json({ error: "schoolId inválido" });

    const school = await prisma.school.findUnique({
      where: { id: schoolId },
      select: {
        id: true,
        name: true,
        responsible: true,
        email: true,
        phone: true,
        royaltiesFee: true,
        payDay: true,
        cep: true,
        city: true,
        uf: true,
        neighborhood: true,
        createdAt: true,
      },
    });

    if (!school) return res.status(404).json({ error: "Escola não encontrada" });

    return res.json({ school });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Erro ao buscar escola" });
  }
});

/** Atualizar dados completos da escola (admin) */
app.patch("/schools/:schoolId", requireAuth, requireAdmin, async (req, res) => {
  try {
    const schoolId = paramStr(req.params.schoolId);
    if (!schoolId) return res.status(400).json({ error: "schoolId inválido" });

    const {
      name,
      responsible,
      email,
      phone,
      royaltiesFee,
      payDay,
      cep,
      city,
      uf,
      neighborhood,
    } = req.body as {
      name?: string;
      responsible?: string;
      email?: string;
      phone?: string;
      royaltiesFee?: number;
      payDay?: number;
      cep?: string | null;
      city?: string | null;
      uf?: string | null;
      neighborhood?: string | null;
    };

    const cleanName = typeof name === "string" ? name.trim() : "";
    const cleanResponsible = typeof responsible === "string" ? responsible.trim() : "";
    const cleanSchoolEmail = cleanEmail(email);
    const cleanSchoolPhone = typeof phone === "string" ? phone.replace(/\D/g, "") : "";

    if (!cleanName) return res.status(400).json({ error: "name é obrigatório" });
    if (!cleanResponsible) return res.status(400).json({ error: "responsible é obrigatório" });
    if (!cleanSchoolEmail || !isValidEmail(cleanSchoolEmail)) {
      return res.status(400).json({ error: "E-mail inválido" });
    }

    if (!(cleanSchoolPhone.length === 10 || cleanSchoolPhone.length === 11)) {
      return res.status(400).json({ error: "Telefone inválido (use DDD + número)" });
    }

    const payDayNum = Number(payDay);
    if (!Number.isFinite(payDayNum) || payDayNum < 1 || payDayNum > 28) {
      return res.status(400).json({ error: "Dia de pagamento deve ser entre 1 e 28" });
    }

    const royaltiesNum = Number(royaltiesFee);
    if (!Number.isFinite(royaltiesNum) || royaltiesNum < 0 || royaltiesNum > 100) {
      return res.status(400).json({ error: "Royalties deve ser entre 0 e 100" });
    }

    const updated = await prisma.school.update({
      where: { id: schoolId },
      data: {
        name: cleanName,
        responsible: cleanResponsible,
        email: cleanSchoolEmail,
        phone: cleanSchoolPhone,
        royaltiesFee: royaltiesNum,
        payDay: payDayNum,
        cep: cep ?? null,
        city: city ?? null,
        uf: uf ?? null,
        neighborhood: neighborhood ?? null,
      },
      select: {
        id: true,
        name: true,
        responsible: true,
        email: true,
        phone: true,
        royaltiesFee: true,
        payDay: true,
        cep: true,
        city: true,
        uf: true,
        neighborhood: true,
        createdAt: true,
      },
    });

    return res.json({ ok: true, school: updated });
  } catch (err: any) {
    if (err?.code === "P2002") {
      return res.status(409).json({ error: "E-mail já está em uso" });
    }
    console.error(err);
    return res.status(500).json({ error: "Erro ao atualizar escola" });
  }
});

/** Excluir escola (admin) */
app.delete("/schools/:schoolId", requireAuth, requireAdmin, async (req, res) => {
  try {
    const schoolId = paramStr(req.params.schoolId);
    if (!schoolId) return res.status(400).json({ error: "schoolId inválido" });

    const existing = await prisma.school.findUnique({
      where: { id: schoolId },
      select: { id: true, name: true },
    });

    if (!existing) {
      return res.status(404).json({ error: "Escola não encontrada" });
    }

    // Com onDelete: Cascade no schema (User.schoolId), os users são removidos junto.
    await prisma.school.delete({ where: { id: schoolId } });

    return res.json({ ok: true, deletedSchoolId: schoolId });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Erro ao excluir escola" });
  }
});

/** Listar escolas (admin) */
app.get("/schools", requireAuth, requireAdmin, async (_req, res) => {
  try {
    const schools = await prisma.school.findMany({
      orderBy: { createdAt: "desc" },
      select: {
        id: true,
        name: true,
        responsible: true,
        email: true,
        royaltiesFee: true,
        payDay: true,
        createdAt: true,
      },
    });

    return res.json({ schools });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Erro ao listar escolas" });
  }
});

/** Criar escola + primeiro usuário responsável (admin) */
app.post("/schools", requireAuth, requireAdmin, async (req, res) => {
  try {
    const {
      name,
      responsible,
      email,
      phone,
      royaltiesFee,
      payDay,
      cep,
      city,
      uf,
      neighborhood,
    } = req.body as {
      name?: string;
      responsible?: string;
      email?: string;
      phone?: string;
      royaltiesFee?: number;
      payDay?: number;
      cep?: string | null;
      city?: string | null;
      uf?: string | null;
      neighborhood?: string | null;
    };

    if (!name || !String(name).trim()) return res.status(400).json({ error: "name é obrigatório" });
    if (!responsible || !String(responsible).trim()) return res.status(400).json({ error: "responsible é obrigatório" });

    const e = cleanEmail(email);
    if (!e || !isValidEmail(e)) return res.status(400).json({ error: "E-mail inválido" });

    const payDayNum = Number(payDay);
    if (!Number.isFinite(payDayNum) || payDayNum < 1 || payDayNum > 28) {
      return res.status(400).json({ error: "Dia de pagamento deve ser entre 1 e 28" });
    }

    const phoneClean = cleanPhone(phone);
    if (phoneClean === "__INVALID__" || phoneClean === null || phoneClean === undefined) {
      return res.status(400).json({ error: "Telefone inválido (use DDD + número)" });
    }

    const royaltiesNum = Number(royaltiesFee);
    if (!Number.isFinite(royaltiesNum) || royaltiesNum < 0 || royaltiesNum > 100) {
      return res.status(400).json({ error: "Royalties deve ser entre 0 e 100" });
    }

    const tempPassword = Math.random().toString(36).slice(-8) + "A1!";
    const passwordHash = await bcrypt.hash(tempPassword, 10);

    const school = await prisma.school.create({
      data: {
        name: String(name).trim(),
        responsible: String(responsible).trim(),
        email: e,
        phone: phoneClean,
        royaltiesFee: royaltiesNum,
        payDay: payDayNum,
        cep: cep ?? null,
        city: city ?? null,
        uf: uf ?? null,
        neighborhood: neighborhood ?? null,
        users: {
          create: {
            name: String(responsible).trim(),
            email: e,
            phone: phoneClean,
            passwordHash,
            tempPassword: true,
          },
        },
      },
      include: { users: true },
    });

    return res.status(201).json({
      school: { id: school.id, name: school.name },
      tempPassword,
    });
  } catch (err: any) {
    if (err?.code === "P2002") {
      return res.status(409).json({ error: "E-mail já cadastrado" });
    }
    console.error(err);
    return res.status(500).json({ error: "Erro ao criar escola" });
  }
});

/* ================== USERS POR ESCOLA ================== */

/** Listar usuários da escola (admin vê qualquer; usuário comum vê só sua escola) */
app.get("/schools/:schoolId/users", requireAuth, async (req, res) => {
  try {
    const schoolId = paramStr(req.params.schoolId);
    if (!schoolId) return res.status(400).json({ error: "schoolId inválido" });

    if (!canAccessSchool(req, schoolId)) {
      return res.status(403).json({ error: "Sem permissão para essa escola" });
    }

    const users = await prisma.user.findMany({
      where: { schoolId },
      select: {
        id: true,
        name: true,
        email: true,
        phone: true,
        tempPassword: true,
        isAdmin: true,
        createdAt: true,
      },
      orderBy: { createdAt: "asc" },
    });

    return res.json({ users });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Erro ao listar usuários" });
  }
});

/** Criar usuário na escola (admin) */
app.post("/schools/:schoolId/users", requireAuth, requireAdmin, async (req, res) => {
  try {
    const schoolId = paramStr(req.params.schoolId);
    if (!schoolId) return res.status(400).json({ error: "schoolId inválido" });

    const { name, email, phone } = req.body as { name?: string; email?: string; phone?: string };

    const cleanName = typeof name === "string" ? name.trim() : "";
    const cleanUserEmail = cleanEmail(email);

    if (!cleanName || !cleanUserEmail) {
      return res.status(400).json({ error: "name e email são obrigatórios" });
    }
    if (!isValidEmail(cleanUserEmail)) {
      return res.status(400).json({ error: "E-mail inválido" });
    }

    const phoneClean = cleanPhone(phone);
    if (phoneClean === "__INVALID__") {
      return res.status(400).json({ error: "Telefone inválido (use DDD + número)" });
    }

    const tempPassword = Math.random().toString(36).slice(-8) + "A1!";
    const passwordHash = await bcrypt.hash(tempPassword, 10);

    const user = await prisma.user.create({
      data: {
        name: cleanName,
        email: cleanUserEmail,
        phone: phoneClean ?? null,
        passwordHash,
        tempPassword: true,
        schoolId,
      },
      select: {
        id: true,
        name: true,
        email: true,
        phone: true,
        tempPassword: true,
        isAdmin: true,
        createdAt: true,
      },
    });

    return res.status(201).json({ user, tempPassword });
  } catch (err: any) {
    if (err?.code === "P2002") {
      return res.status(409).json({ error: "E-mail já cadastrado" });
    }
    console.error(err);
    return res.status(500).json({ error: "Erro ao criar usuário" });
  }
});

/** Atualizar usuário na escola (admin) */
app.patch("/schools/:schoolId/users/:userId", requireAuth, requireAdmin, async (req, res) => {
  try {
    const schoolId = paramStr(req.params.schoolId);
    const userId = paramStr(req.params.userId);

    if (!schoolId || !userId) {
      return res.status(400).json({ error: "Parâmetros inválidos" });
    }

    const { name, email, phone, tempPassword, isAdmin, newPassword } = req.body as {
      name?: string;
      email?: string;
      phone?: string | null;
      tempPassword?: boolean;
      isAdmin?: boolean;
      newPassword?: string;
    };

    const cleanName = typeof name === "string" ? name.trim() : undefined;
    const cleanUserEmail = cleanEmail(email);
    const cleanUserPhone = cleanPhone(phone);
    const cleanTempPassword = typeof tempPassword === "boolean" ? tempPassword : undefined;
    const cleanIsAdmin = typeof isAdmin === "boolean" ? isAdmin : undefined;
    const cleanNewPassword = typeof newPassword === "string" ? newPassword.trim() : undefined;

    const sentAnyField =
      cleanName !== undefined ||
      cleanUserEmail !== undefined ||
      cleanUserPhone !== undefined ||
      cleanTempPassword !== undefined ||
      cleanIsAdmin !== undefined ||
      (cleanNewPassword !== undefined && cleanNewPassword.length > 0);

    if (!sentAnyField) {
      return res.status(400).json({ error: "Envie pelo menos 1 campo para atualizar" });
    }

    if (cleanUserEmail && !isValidEmail(cleanUserEmail)) {
      return res.status(400).json({ error: "E-mail inválido" });
    }

    if (cleanUserPhone === "__INVALID__") {
      return res.status(400).json({ error: "Telefone inválido (use DDD + número)" });
    }

    if (cleanNewPassword && cleanNewPassword.length < 6) {
      return res.status(400).json({ error: "Senha deve ter no mínimo 6 caracteres" });
    }

    const existing = await prisma.user.findFirst({
      where: { id: userId, schoolId },
      select: { id: true },
    });

    if (!existing) {
      return res.status(404).json({ error: "Usuário não encontrado nesta escola" });
    }

    let passwordHashToSet: string | undefined = undefined;
    if (cleanNewPassword && cleanNewPassword.length > 0) {
      passwordHashToSet = await bcrypt.hash(cleanNewPassword, 10);
    }

    const updated = await prisma.user.update({
      where: { id: userId },
      data: {
        ...(cleanName ? { name: cleanName } : {}),
        ...(cleanUserEmail ? { email: cleanUserEmail } : {}),
        ...(cleanUserPhone !== undefined ? { phone: cleanUserPhone } : {}),
        ...(cleanTempPassword !== undefined ? { tempPassword: cleanTempPassword } : {}),
        ...(cleanIsAdmin !== undefined ? { isAdmin: cleanIsAdmin } : {}),
        ...(passwordHashToSet ? { passwordHash: passwordHashToSet } : {}),
      },
      select: {
        id: true,
        name: true,
        email: true,
        phone: true,
        tempPassword: true,
        isAdmin: true,
        createdAt: true,
      },
    });

    return res.json({ ok: true, user: updated });
  } catch (err: any) {
    if (err?.code === "P2002") {
      return res.status(409).json({ error: "E-mail já está em uso" });
    }
    console.error(err);
    return res.status(500).json({ error: "Erro ao atualizar usuário" });
  }
});

/** Resetar senha (admin) */
app.post("/schools/:schoolId/users/:userId/reset-password", requireAuth, requireAdmin, async (req, res) => {
  try {
    const schoolId = paramStr(req.params.schoolId);
    const userId = paramStr(req.params.userId);

    if (!schoolId || !userId) {
      return res.status(400).json({ error: "Parâmetros inválidos" });
    }

    const user = await prisma.user.findFirst({
      where: { id: userId, schoolId },
      select: { id: true, email: true },
    });

    if (!user) {
      return res.status(404).json({ error: "Usuário não encontrado" });
    }

    const tempPassword = Math.random().toString(36).slice(-8) + "A1!";
    const passwordHash = await bcrypt.hash(tempPassword, 10);

    await prisma.user.update({
      where: { id: userId },
      data: { passwordHash, tempPassword: true },
    });

    return res.json({
      ok: true,
      userId,
      email: user.email,
      tempPassword,
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Erro ao resetar senha" });
  }
});

/* ================== START ================== */


const PORT = Number(process.env.PORT) || 3000;

app.listen(PORT, "0.0.0.0", () => {
  console.log(`API rodando na porta ${PORT}`);
});
