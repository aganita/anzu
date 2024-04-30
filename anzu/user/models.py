# -*- coding: utf-8 -*-
"""User models."""
import datetime as dt

from flask_login import UserMixin
from sqlalchemy.ext.hybrid import hybrid_property

from anzu.database import Column, PkModel, db, reference_col, relationship
from anzu.extensions import bcrypt

import uuid


class Role(PkModel):
    """A role for a user."""

    __tablename__ = "roles"
    name = Column(db.String(80), unique=True, nullable=False)
    user_id = reference_col("users", nullable=True)
    user = relationship("User", backref="roles")

    def __init__(self, name, **kwargs):
        """Create instance."""
        super().__init__(name=name, **kwargs)

    def __repr__(self):
        """Represent instance as a unique string."""
        return f"<Role({self.name})>"


class User(UserMixin, PkModel):
    """A user of the app."""

    __tablename__ = "users"
    username = Column(db.String(80), unique=True, nullable=False)
    email = Column(db.String(80), unique=True, nullable=False)
    _password = Column("password", db.LargeBinary(128), nullable=True)
    created_at = Column(db.DateTime, nullable=False, default=dt.datetime.utcnow)
    first_name = Column(db.String(30), nullable=True)
    last_name = Column(db.String(30), nullable=True)
    active = Column(db.Boolean(), default=False)
    is_admin = Column(db.Boolean(), default=False)

    @hybrid_property
    def password(self):
        """Hashed password."""
        return self._password

    @password.setter
    def password(self, value):
        """Set password."""
        self._password = bcrypt.generate_password_hash(value)

    def check_password(self, value):
        """Check password."""
        return bcrypt.check_password_hash(self._password, value)

    @property
    def full_name(self):
        """Full user name."""
        return f"{self.first_name} {self.last_name}"

    def __repr__(self):
        """Represent instance as a unique string."""
        return f"<User({self.username!r})>"


class Device(PkModel):
    """A device on the network."""

    __tablename__ = "devices"
    mac_address = Column(db.String(80), unique=True, nullable=False)
    ip_address = Column(db.String(80), unique=False, nullable=False)
    type = Column(db.String(80), nullable=True)
    manufacturer = Column(db.String(80), nullable=False)
    open_ports = Column(db.String(80), nullable=True)
    risk_score = Column(db.String(80), nullable=True)

    def __init__(self, mac_address, ip_address, type, manufacturer, open_ports, risk_score, **kwargs):
        """Create instance."""
        print(f"Creating device ${mac_address}, ${ip_address}, ${type}, ${manufacturer}, ${open_ports}, ${risk_score}")
        super().__init__(mac_address=mac_address, ip_address=ip_address, type=type, manufacturer=manufacturer, open_ports=open_ports, risk_score=risk_score, **kwargs)

    def __repr__(self):
        """Represent instance as a unique string."""
        return f"<Device({self.mac_address!r})>"
    
    @classmethod
    def update_device(cls, mac_address, ip_address=None, type=None, manufacturer=None, open_ports=None, risk_score=None):
        """Update device details."""
        device = cls.query.filter_by(mac_address=mac_address).first()
        if not device:
            return False  # Device not found

        if ip_address is not None:
            device.ip_address = ip_address
        if type is not None:
            device.type = type
        if manufacturer is not None:
            device.manufacturer = manufacturer
        if open_ports is not None:
            device.open_ports = open_ports
        if risk_score is not None:
            device.risk_score = risk_score

        db.session.commit()
        return True


# class Alerts(PkModel):
#     """Network alerts."""

#     __tablename__ = "alerts"
#     id = Column(db.String(80), unique=True, nullable=False)
#     name = Column(db.String(160), unique=True, nullable=False)
#     description = Column(db.String(300), unique=False, nullable=True)

#     def __init__(self, name, description, **kwargs):
#         """Create instance."""
#         super().__init__(id=uuid.uuid1(), name=name, description=description, **kwargs)

#     def __repr__(self):
#         """Represent instance as a unique string."""
#         return f"<Alerts({self.name!r})>"
